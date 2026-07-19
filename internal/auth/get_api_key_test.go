package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers   http.Header
		wantKey   string
		wantErr   error
		wantErrIs bool // when true, compare error with errors.Is against wantErr
	}{
		"valid api key": {
			headers:   http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey:   "my-secret-key",
			wantErr:   nil,
			wantErrIs: true,
		},
		"no authorization header": {
			headers:   http.Header{},
			wantKey:   "",
			wantErr:   ErrNoAuthHeaderIncluded,
			wantErrIs: false,
		},
		"empty authorization header": {
			headers:   http.Header{"Authorization": []string{""}},
			wantKey:   "",
			wantErr:   ErrNoAuthHeaderIncluded,
			wantErrIs: true,
		},
		"malformed - wrong scheme": {
			headers: http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		"malformed - missing key": {
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		"malformed - only whitespace value": {
			headers: http.Header{"Authorization": []string{"ApiKey "}},
			wantKey: "",
			wantErr: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tc.headers)

			if gotKey != tc.wantKey {
				t.Errorf("GetAPIKey() key = %q, want %q", gotKey, tc.wantKey)
			}

			switch {
			case tc.wantErr == nil:
				if gotErr != nil {
					t.Errorf("GetAPIKey() error = %v, want nil", gotErr)
				}
			case tc.wantErrIs:
				if !errors.Is(gotErr, tc.wantErr) {
					t.Errorf("GetAPIKey() error = %v, want %v", gotErr, tc.wantErr)
				}
			default:
				if gotErr == nil || gotErr.Error() != tc.wantErr.Error() {
					t.Errorf("GetAPIKey() error = %v, want %v", gotErr, tc.wantErr)
				}
			}
		})
	}
}
