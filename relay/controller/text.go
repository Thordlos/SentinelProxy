package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/sentinelproxy/sentinelproxy/common/config"
	"github.com/sentinelproxy/sentinelproxy/common/helper"
	"github.com/sentinelproxy/sentinelproxy/common/logger"
	"github.com/sentinelproxy/sentinelproxy/relay"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor/openai"
	"github.com/sentinelproxy/sentinelproxy/relay/apitype"
	"github.com/sentinelproxy/sentinelproxy/relay/billing"
	billingratio "github.com/sentinelproxy/sentinelproxy/relay/billing/ratio"
	"github.com/sentinelproxy/sentinelproxy/relay/channeltype"
	"github.com/sentinelproxy/sentinelproxy/relay/meta"
	"github.com/sentinelproxy/sentinelproxy/relay/model"
	"github.com/sentinelproxy/sentinelproxy/relay/redaction"
	"github.com/sentinelproxy/sentinelproxy/relay/relaymode"
)

func RelayTextHelper(c *gin.Context) *model.ErrorWithStatusCode {
	ctx := c.Request.Context()
	meta := meta.GetByContext(c)
	// get & validate textRequest
	textRequest, err := getAndValidateTextRequest(c, meta.Mode)
	if err != nil {
		logger.Errorf(ctx, "getAndValidateTextRequest failed: %s", err.Error())
		return openai.ErrorWrapper(err, "invalid_text_request", http.StatusBadRequest)
	}
	meta.IsStream = textRequest.Stream

	// ===== SentinelProxy: 请求脱敏 =====
	if redaction.IsEnabled() && meta.Mode == relaymode.ChatCompletions {
		sm := redaction.GetSessionManager()
		state, err := sm.GetState(c)
		if err != nil && redaction.Config().FailClosed {
			logger.Errorf(ctx, "get masking state failed: %s", err.Error())
			return openai.ErrorWrapper(err, "redaction_state_failed", http.StatusInternalServerError)
		}
		if state != nil {
			if err := redaction.RedactRequest(textRequest, state); err != nil {
				if redaction.Config().FailClosed {
					logger.Errorf(ctx, "redact request failed: %s", err.Error())
					return openai.ErrorWrapper(err, "redaction_failed", http.StatusInternalServerError)
				}
				logger.Warnf(ctx, "redact request failed (fail-open): %s", err.Error())
			}
		}
	}
	// ===================================

	// map model name
	meta.OriginModelName = textRequest.Model
	textRequest.Model, _ = getMappedModelName(textRequest.Model, meta.ModelMapping)
	meta.ActualModelName = textRequest.Model
	// set system prompt if not empty
	systemPromptReset := setSystemPrompt(ctx, textRequest, meta.ForcedSystemPrompt)
	// get model ratio & group ratio
	modelRatio := billingratio.GetModelRatio(textRequest.Model, meta.ChannelType)
	groupRatio := billingratio.GetGroupRatio(meta.Group)
	ratio := modelRatio * groupRatio
	// pre-consume quota
	promptTokens := getPromptTokens(textRequest, meta.Mode)
	meta.PromptTokens = promptTokens
	preConsumedQuota, bizErr := preConsumeQuota(ctx, textRequest, promptTokens, ratio, meta)
	if bizErr != nil {
		logger.Warnf(ctx, "preConsumeQuota failed: %+v", *bizErr)
		return bizErr
	}

	adaptor := relay.GetAdaptor(meta.APIType)
	if adaptor == nil {
		return openai.ErrorWrapper(fmt.Errorf("invalid api type: %d", meta.APIType), "invalid_api_type", http.StatusBadRequest)
	}
	adaptor.Init(meta)

	// get request body
	// SentinelProxy: 如果启用了脱敏，必须重新 marshal 请求体以包含脱敏后的内容
	var requestBody io.Reader
	if redaction.IsEnabled() {
		convertedRequest, err := adaptor.ConvertRequest(c, meta.Mode, textRequest)
		if err != nil {
			return openai.ErrorWrapper(err, "convert_request_failed", http.StatusInternalServerError)
		}
		jsonData, err := json.Marshal(convertedRequest)
		if err != nil {
			return openai.ErrorWrapper(err, "marshal_request_failed", http.StatusInternalServerError)
		}
		requestBody = bytes.NewBuffer(jsonData)
		if redaction.Config().LogRawRequests {
			requestId := helper.GetRequestID(c.Request.Context())
			redaction.RecordRawRequestAfterRedaction(requestId, jsonData)
			logger.Infof(c.Request.Context(), "[RAW REQUEST AFTER REDACTION] %s", string(jsonData))
		} else {
			logger.Debugf(c.Request.Context(), "converted request after redaction: \n%s", string(jsonData))
		}
	} else {
		requestBody, err = getRequestBody(c, meta, textRequest, adaptor)
		if err != nil {
			return openai.ErrorWrapper(err, "convert_request_failed", http.StatusInternalServerError)
		}
	}

	// do request
	resp, err := adaptor.DoRequest(c, meta, requestBody)
	if err != nil {
		logger.Errorf(ctx, "DoRequest failed: %s", err.Error())
		return openai.ErrorWrapper(err, "do_request_failed", http.StatusInternalServerError)
	}
	if isErrorHappened(meta, resp) {
		billing.ReturnPreConsumedQuota(ctx, preConsumedQuota, meta.TokenId)
		return RelayErrorHandler(resp)
	}

	// do response
	usage, respErr := adaptor.DoResponse(c, resp, meta)
	if respErr != nil {
		logger.Errorf(ctx, "respErr is not nil: %+v", respErr)
		billing.ReturnPreConsumedQuota(ctx, preConsumedQuota, meta.TokenId)
		return respErr
	}
	// post-consume quota
	go postConsumeQuota(ctx, usage, meta, textRequest, ratio, preConsumedQuota, modelRatio, groupRatio, systemPromptReset)
	return nil
}

func getRequestBody(c *gin.Context, meta *meta.Meta, textRequest *model.GeneralOpenAIRequest, adaptor adaptor.Adaptor) (io.Reader, error) {
	if !config.EnforceIncludeUsage &&
		meta.APIType == apitype.OpenAI &&
		meta.OriginModelName == meta.ActualModelName &&
		meta.ChannelType != channeltype.Baichuan &&
		meta.ForcedSystemPrompt == "" {
		// no need to convert request for openai
		return c.Request.Body, nil
	}

	// get request body
	var requestBody io.Reader
	convertedRequest, err := adaptor.ConvertRequest(c, meta.Mode, textRequest)
	if err != nil {
		logger.Debugf(c.Request.Context(), "converted request failed: %s\n", err.Error())
		return nil, err
	}
	jsonData, err := json.Marshal(convertedRequest)
	if err != nil {
		logger.Debugf(c.Request.Context(), "converted request json_marshal_failed: %s\n", err.Error())
		return nil, err
	}
	if redaction.Config().LogRawRequests {
		requestId := helper.GetRequestID(c.Request.Context())
		redaction.RecordRawRequestConverted(requestId, jsonData)
		logger.Infof(c.Request.Context(), "[RAW REQUEST CONVERTED] %s", string(jsonData))
	} else {
		logger.Debugf(c.Request.Context(), "converted request: \n%s", string(jsonData))
	}
	requestBody = bytes.NewBuffer(jsonData)
	return requestBody, nil
}
