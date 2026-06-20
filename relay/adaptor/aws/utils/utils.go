package utils

import (
	"net/http"

	relaymodel "github.com/sentinelproxy/sentinelproxy/relay/model"
)

func WrapErr(err error) *relaymodel.ErrorWithStatusCode {
	return &relaymodel.ErrorWithStatusCode{
		StatusCode: http.StatusInternalServerError,
		Error: relaymodel.Error{
			Message: err.Error(),
		},
	}
}
