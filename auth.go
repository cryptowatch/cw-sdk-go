package streamclient

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"time"

	pbc "github.com/cryptowatch/proto/client"
	pbs "github.com/cryptowatch/proto/stream"
)

// authenticate is used as a state change listener for StateConnected. That is
// to say, once the client connects, it attempts to authenticate.
func authenticate(conn *StreamConn, oldState, state State, cause error) {
	nonce := getNonce()
	authMsg := &pbc.ClientMessage{
		Body: &pbc.ClientMessage_SdkAuthentication{
			SdkAuthentication: &pbc.SDKClientAuthenticationMessage{
				Token:       conn.generateToken(nonce),
				Nonce:       nonce,
				AccessKeyId: conn.params.accessKeyId,
				Source:      pbc.SDKClientAuthenticationMessage_GOLANG_SDK,
			},
		},
	}
	if err := conn.sendProto(authMsg); err != nil {
		// Not much we can do here
	}
}

func (c *StreamConn) authResponseHandler(authRes *pbs.AuthenticationResult) {
	switch authRes.Status {
	case AuthenticationResult_AUTHENTICATED:
		c.mtx.Lock()
		c.updateState(StateAuthenticated, nil)
		println("authenticated")
		c.mtx.Unlock()
	case AuthenticationResult_TOKEN_MISMATCH:
	case AuthenticationResult_TOKEN_EXPIRED:
	case AuthenticationResult_BAD_NONCE:
	case AuthenticationResult_UNKNOWN:
	}
}

// generateToken creates an access token based on the user's secret access key
func (c *StreamConn) generateToken(nonce string) string {
	h := hmac.New(sha512.New, []byte(c.params.secretAccessKey))
	payload := fmt.Sprintf("stream_access;access_key_id=%v;nonce=%v;", c.params.accessKeyId, nonce)
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

func getNonce() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
