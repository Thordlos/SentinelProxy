package openai

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sentinelproxy/sentinelproxy/common"
	"github.com/sentinelproxy/sentinelproxy/common/conv"
	"github.com/sentinelproxy/sentinelproxy/common/logger"
	"github.com/sentinelproxy/sentinelproxy/common/render"
	"github.com/sentinelproxy/sentinelproxy/relay/model"
	"github.com/sentinelproxy/sentinelproxy/relay/redaction"
	"github.com/sentinelproxy/sentinelproxy/relay/relaymode"
)

const (
	dataPrefix       = "data: "
	done             = "[DONE]"
	dataPrefixLength = len(dataPrefix)
)

func StreamHandler(c *gin.Context, resp *http.Response, relayMode int) (*model.ErrorWithStatusCode, string, *model.Usage) {
	responseText := ""
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	var usage *model.Usage

	// ===== SentinelProxy: 初始化流式恢复器 =====
	var unmasker *redaction.StreamingUnmasker
	if state := redaction.GetStateFromContext(c); state != nil {
		unmasker = redaction.NewStreamingUnmasker(state)
	}
	// ============================================

	common.SetEventStreamHeaders(c)

	doneRendered := false
	for scanner.Scan() {
		data := scanner.Text()
		if len(data) < dataPrefixLength { // ignore blank line or wrong format
			continue
		}
		if data[:dataPrefixLength] != dataPrefix && data[:dataPrefixLength] != done {
			continue
		}
		if strings.HasPrefix(data[dataPrefixLength:], done) {
			render.StringData(c, data)
			doneRendered = true
			continue
		}
		switch relayMode {
		case relaymode.ChatCompletions:
			var streamResponse ChatCompletionsStreamResponse
			err := json.Unmarshal([]byte(data[dataPrefixLength:]), &streamResponse)
			if err != nil {
				logger.SysError("error unmarshalling stream response: " + err.Error())
				render.StringData(c, data) // if error happened, pass the data to client
				continue                   // just ignore the error
			}
			if len(streamResponse.Choices) == 0 && streamResponse.Usage == nil {
				// but for empty choice and no usage, we should not pass it to client, this is for azure
				continue // just ignore empty choice
			}

			// ===== SentinelProxy: 流式实时恢复 =====
			modified := false
			for i := range streamResponse.Choices {
				content := conv.AsString(streamResponse.Choices[i].Delta.Content)
				if content != "" {
					responseText += content
					if unmasker != nil {
						recovered := unmasker.Write(content)
						streamResponse.Choices[i].Delta.Content = recovered
						modified = true
					}
				}

				// 处理 tool_calls 的 arguments
				for j := range streamResponse.Choices[i].Delta.ToolCalls {
					args := conv.AsString(streamResponse.Choices[i].Delta.ToolCalls[j].Function.Arguments)
					if args != "" {
						responseText += args
						if unmasker != nil {
							recovered := unmasker.Write(args)
							streamResponse.Choices[i].Delta.ToolCalls[j].Function.Arguments = recovered
							modified = true
						}
					}
				}
			}
			if modified {
				newJson, err := json.Marshal(streamResponse)
				if err == nil {
					data = dataPrefix + string(newJson)
				}
			}
			// ========================================

			render.StringData(c, data)
			if streamResponse.Usage != nil {
				usage = streamResponse.Usage
			}
		case relaymode.Completions:
			render.StringData(c, data)
			var streamResponse CompletionsStreamResponse
			err := json.Unmarshal([]byte(data[dataPrefixLength:]), &streamResponse)
			if err != nil {
				logger.SysError("error unmarshalling stream response: " + err.Error())
				continue
			}
			for _, choice := range streamResponse.Choices {
				responseText += choice.Text
			}
		}
	}

	if err := scanner.Err(); err != nil {
		logger.SysError("error reading stream: " + err.Error())
	}

	// ===== SentinelProxy: flush 剩余 pending =====
	if unmasker != nil {
		remaining := unmasker.Flush()
		if remaining != "" {
			finalChunk := buildFinalStreamChunk(remaining)
			if finalChunk != "" {
				render.StringData(c, dataPrefix+finalChunk)
			}
		}
	}
	// =============================================

	if !doneRendered {
		render.Done(c)
	}

	err := resp.Body.Close()
	if err != nil {
		return ErrorWrapper(err, "close_response_body_failed", http.StatusInternalServerError), "", nil
	}

	if redaction.Config().LogRawRequests {
		logger.Infof(c.Request.Context(), "[RAW RESPONSE STREAM] %s", responseText)
	}

	return nil, responseText, usage
}

// buildFinalStreamChunk 构造一个包含剩余文本的 SSE chunk
func buildFinalStreamChunk(text string) string {
	resp := ChatCompletionsStreamResponse{
		Choices: []ChatCompletionsStreamResponseChoice{
			{
				Delta: model.Message{
					Role:    "assistant",
					Content: text,
				},
			},
		},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return ""
	}
	return string(data)
}

func Handler(c *gin.Context, resp *http.Response, promptTokens int, modelName string) (*model.ErrorWithStatusCode, *model.Usage) {
	var textResponse SlimTextResponse
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrorWrapper(err, "read_response_body_failed", http.StatusInternalServerError), nil
	}
	err = resp.Body.Close()
	if err != nil {
		return ErrorWrapper(err, "close_response_body_failed", http.StatusInternalServerError), nil
	}

	// ===== SentinelProxy: 非流式响应恢复 =====
	if state := redaction.GetStateFromContext(c); state != nil {
		if redaction.Config().LogRawRequests {
			logger.Infof(c.Request.Context(), "[RAW RESPONSE FROM UPSTREAM] %s", string(responseBody))
		}
		responseBody = redaction.UnmaskBytes(responseBody, state)
		if redaction.Config().LogRawRequests {
			logger.Infof(c.Request.Context(), "[RAW RESPONSE] %s", string(responseBody))
		}
	} else if redaction.Config().LogRawRequests {
		logger.Infof(c.Request.Context(), "[RAW RESPONSE] %s", string(responseBody))
	}
	// ==========================================

	err = json.Unmarshal(responseBody, &textResponse)
	if err != nil {
		return ErrorWrapper(err, "unmarshal_response_body_failed", http.StatusInternalServerError), nil
	}
	if textResponse.Error.Type != "" {
		return &model.ErrorWithStatusCode{
			Error:      textResponse.Error,
			StatusCode: resp.StatusCode,
		}, nil
	}
	// Reset response body
	resp.Body = io.NopCloser(bytes.NewBuffer(responseBody))

	// We shouldn't set the header before we parse the response body, because the parse part may fail.
	// And then we will have to send an error response, but in this case, the header has already been set.
	// So the HTTPClient will be confused by the response.
	// For example, Postman will report error, and we cannot check the response at all.
	for k, v := range resp.Header {
		c.Writer.Header().Set(k, v[0])
	}
	c.Writer.WriteHeader(resp.StatusCode)
	_, err = io.Copy(c.Writer, resp.Body)
	if err != nil {
		return ErrorWrapper(err, "copy_response_body_failed", http.StatusInternalServerError), nil
	}
	err = resp.Body.Close()
	if err != nil {
		return ErrorWrapper(err, "close_response_body_failed", http.StatusInternalServerError), nil
	}

	if textResponse.Usage.TotalTokens == 0 || (textResponse.Usage.PromptTokens == 0 && textResponse.Usage.CompletionTokens == 0) {
		completionTokens := 0
		for _, choice := range textResponse.Choices {
			completionTokens += CountTokenText(choice.Message.StringContent(), modelName)
		}
		textResponse.Usage = model.Usage{
			PromptTokens:     promptTokens,
			CompletionTokens: completionTokens,
			TotalTokens:      promptTokens + completionTokens,
		}
	}
	return nil, &textResponse.Usage
}
