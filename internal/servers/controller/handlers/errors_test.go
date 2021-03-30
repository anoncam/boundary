package handlers

import (
	"context"
	stderrors "errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/hashicorp/boundary/internal/errors"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestApiErrorHandler(t *testing.T) {
	ctx := context.Background()
	req, err := http.NewRequest("GET", "madeup/for/the/test", nil)
	require.NoError(t, err)
	mux := runtime.NewServeMux()
	inMarsh, outMarsh := runtime.MarshalerForRequest(mux, req)

	tested := ErrorHandler(hclog.L())

	testCases := []struct {
		name     string
		err      error
		expected apiError
	}{
		{
			name: "Not Found",
			err:  NotFoundErrorf("Test"),
			expected: apiError{
				status: http.StatusNotFound,
				inner: &pb.Error{
					Kind:    "NotFound",
					Message: "Test",
				},
			},
		},
		{
			name: "Invalid Fields",
			err: InvalidArgumentErrorf("Test", map[string]string{
				"k1": "v1",
				"k2": "v2",
			}),
			expected: apiError{
				status: http.StatusBadRequest,
				inner: &pb.Error{
					Kind:    "InvalidArgument",
					Message: "Test",
					Details: &pb.ErrorDetails{
						RequestFields: []*pb.FieldError{
							{
								Name:        "k1",
								Description: "v1",
							},
							{
								Name:        "k2",
								Description: "v2",
							},
						},
					},
				},
			},
		},
		{
			name: "GrpcGateway Routing Error",
			err:  runtime.ErrNotMatch,
			expected: apiError{
				status: http.StatusNotFound,
				inner: &pb.Error{
					Kind:    "NotFound",
					Message: http.StatusText(http.StatusNotFound),
				},
			},
		},
		{
			name: "Unimplemented error",
			err:  status.Error(codes.Unimplemented, "Test"),
			expected: apiError{
				status: http.StatusMethodNotAllowed,
				inner: &pb.Error{
					Kind:    "Unimplemented",
					Message: "Test",
				},
			},
		},
		{
			name: "Unknown error",
			err:  stderrors.New("Some random error"),
			expected: apiError{
				status: http.StatusInternalServerError,
				inner: &pb.Error{
					Kind:    "Internal",
					Message: "Some random error",
				},
			},
		},
		{
			name: "Domain error Db invalid public id",
			err:  errors.E(errors.WithCode(errors.InvalidPublicId)),
			expected: apiError{
				status: http.StatusInternalServerError,
				inner: &pb.Error{
					Kind:    "Internal",
					Message: "invalid public id, parameter violation: error #102",
				},
			},
		},
		{
			name: "Domain error Db invalid parameter",
			err:  errors.E(errors.WithCode(errors.InvalidParameter)),
			expected: apiError{
				status: http.StatusInternalServerError,
				inner: &pb.Error{
					Kind:    "Internal",
					Message: "invalid parameter, parameter violation: error #100",
				},
			},
		},
		{
			name: "Domain error Db invalid field mask",
			err:  errors.E(errors.WithCode(errors.InvalidFieldMask)),
			expected: apiError{
				status: http.StatusBadRequest,
				inner: &pb.Error{
					Kind:    "InvalidArgument",
					Message: "Error in provided request",
					Details: &pb.ErrorDetails{RequestFields: []*pb.FieldError{{Name: "update_mask", Description: "Invalid update mask provided."}}},
				},
			},
		},
		{
			name: "Domain error Db empty field mask",
			err:  errors.E(errors.WithCode(errors.EmptyFieldMask)),
			expected: apiError{
				status: http.StatusBadRequest,
				inner: &pb.Error{
					Kind:    "InvalidArgument",
					Message: "Error in provided request",
					Details: &pb.ErrorDetails{RequestFields: []*pb.FieldError{{Name: "update_mask", Description: "Invalid update mask provided."}}},
				},
			},
		},
		{
			name: "Domain error Db not unqiue",
			err:  errors.E(errors.WithCode(errors.NotUnique)),
			expected: apiError{
				status: http.StatusBadRequest,
				inner: &pb.Error{
					Kind:    "InvalidArgument",
					Message: genericUniquenessMsg,
				},
			},
		},
		{
			name: "Domain error Db record not found",
			err:  errors.E(errors.WithCode(errors.RecordNotFound)),
			expected: apiError{
				status: http.StatusNotFound,
				inner: &pb.Error{
					Kind:    "NotFound",
					Message: genericNotFoundMsg,
				},
			},
		},
		{
			name: "Domain error Db multiple records",
			err:  errors.E(errors.WithCode(errors.MultipleRecords)),
			expected: apiError{
				status: http.StatusInternalServerError,
				inner: &pb.Error{
					Kind:    "Internal",
					Message: "multiple records, search issue: error #1101",
				},
			},
		},
		{
			name: "Domain error account already associated",
			err:  errors.E(errors.WithCode(errors.AccountAlreadyAssociated)),
			expected: apiError{
				status: http.StatusBadRequest,
				inner: &pb.Error{
					Kind:    "InvalidArgument",
					Message: "account already associated with another user, parameter violation: error #114",
				},
			},
		},
		{
			name: "Wrapped domain error",
			err:  errors.E(errors.WithCode(errors.InvalidAddress), errors.WithMsg("test msg"), errors.WithWrap(errors.E(errors.WithCode(errors.NotNull), errors.WithMsg("inner msg")))),
			expected: apiError{
				status: http.StatusInternalServerError,
				inner: &pb.Error{
					Kind:    "Internal",
					Message: "test msg: parameter violation: error #101: inner msg: integrity violation: error #1001",
				},
			},
		},
		{
			name: "Forbidden domain error",
			err:  errors.E(errors.WithCode(errors.Forbidden), errors.WithMsg("test msg")),
			expected: apiError{
				status: http.StatusForbidden,
				inner: &pb.Error{
					Kind:    "Internal",
					Message: "test msg: unknown: error #403",
				},
			},
		},
		{
			name: "Wrapped forbidden domain error",
			err:  fmt.Errorf("got error: %w", errors.E(errors.WithCode(errors.Forbidden), errors.WithMsg("test msg"))),
			expected: apiError{
				status: http.StatusForbidden,
				inner: &pb.Error{
					Kind:    "Internal",
					Message: "got error: test msg: unknown: error #403",
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			w := httptest.NewRecorder()
			tested(ctx, mux, outMarsh, w, req, tc.err)
			resp := w.Result()
			assert.EqualValues(tc.expected.status, resp.StatusCode)

			got, err := ioutil.ReadAll(resp.Body)
			require.NoError(err)

			gotErr := &pb.Error{}
			err = inMarsh.Unmarshal(got, gotErr)
			require.NoError(err)

			assert.Equal(tc.expected.status, int32(resp.StatusCode))
			assert.Empty(cmp.Diff(tc.expected.inner, gotErr, protocmp.Transform()))
		})
	}
}
