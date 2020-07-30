package errors

import "net/http"

// RestErr is a commong Rest Error
type RestErr struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
	Error   string `json:"error"`
}

// NewBadRequestError returns new Bad request error
func NewBadRequestError(message string) *RestErr {

	return &RestErr{
		Message: message,
		Code:    http.StatusBadRequest,
		Error:   "bad_request",
	}
}

// NewNotFoundError returns new Bad request error
func NewNotFoundError(message string) *RestErr {

	return &RestErr{
		Message: message,
		Code:    http.StatusNotFound,
		Error:   "bad_request",
	}
}

// NewInternalServerError returns new Bad request error
func NewInternalServerError(message string) *RestErr {

	return &RestErr{
		Message: message,
		Code:    http.StatusInternalServerError,
		Error:   "internal_server_error",
	}
}
