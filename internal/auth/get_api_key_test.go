package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers http.Header
		wantKey string
		wantErr error
	}{
		"valid api key": {
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
			wantErr: nil,
		},
		"no authorization header": {
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		"empty authorization header": {
			headers: http.Header{"Authorization": []string{""}},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		"wrong scheme": {
			headers: http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			wantKey: "",
			wantErr: ErrMalformedAuthHeader,
		},
		"missing key": {
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			wantKey: "",
			wantErr: ErrMalformedAuthHeader,
		},
		"scheme with empty key": {
			headers: http.Header{"Authorization": []string{"ApiKey "}},
			wantKey: "",
			wantErr: ErrMalformedAuthHeader,
		},
		"scheme with extra space before key": {
			headers: http.Header{"Authorization": []string{"ApiKey  my-secret-key"}},
			wantKey: "",
			wantErr: ErrMalformedAuthHeader,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tc.headers)

			if gotKey != tc.wantKey {
				t.Errorf("GetAPIKey() key = %q, want %q", gotKey, tc.wantKey)
			}

			if !errors.Is(gotErr, tc.wantErr) {
				t.Errorf("GetAPIKey() error = %v, want %v", gotErr, tc.wantErr)
			}
		})
	}
}
