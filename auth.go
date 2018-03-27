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

// authenticateOnConnect is used as a state change listener for StateConnected. That is
// to say, once the client connects, it attempts to authenticate.
func authenticateOnConnect(conn *StreamConn, oldState, state State, cause error) {
	conn.sendAuthRequest()
}

func (c *StreamConn) sendAuthRequest() {
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
		// Good news. no-op
	case AuthenticationResult_TOKEN_EXPIRED:
		// Since the token is expired, we can just try to authenticate again
		c.sendAuthRequest()
	case AuthenticationResult_TOKEN_MISMATCH:
		c.updateState(StateDisconnected, ErrBadCredentials)
		c.closeInternal(websocket.FormatCloseMessage(websocket.CloseProtocolError, ""), true)
	case AuthenticationResult_BAD_NONCE,
		AuthenticationResult_UNKNOWN:
		// If this case hits, that means there is something wrong with their credentials
		c.closeInternal(websocket.FormatCloseMessage(websocket.CloseProtocolError, ""), true)
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
