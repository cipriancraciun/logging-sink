

package lib


import "encoding/json"
import "time"




type Message struct {
	
	Schema string `json:"schema"`
	
	Sequence uint64 `json:"sequence"`
	Timestamp time.Time `json:"timestamp"`
	TimestampUnix uint64 `json:"timestamp_unix"`
	CollectorType string `json:"collector_type,omitempty"`
	CollectorIdentifier string `json:"collector_identifier,omitempty"`
	
	MessageRaw []byte `json:"message_raw,omitempty"`
	MessageSha256 string `json:"message_sha256,omitempty"`
	MessageText string `json:"message_text,omitempty"`
	MessageJson json.RawMessage `json:"message_json,omitempty"`
	MessageExtra json.RawMessage `json:"message_extra,omitempty"`
	MessageMetaData interface{} `json:"message_metadata,omitempty"`
}


const MessageSchema = "20181020b"




type CollectorMessage struct {
	
	CollectorType string
	CollectorIdentifier string
	CollectorTimestamp time.Time
	
	MessageRaw []byte
	MessageSha256 string
	MessageText string
	MessageJson json.RawMessage
	MessageMetaData interface{}
}


type SyslogMessageMetaData struct {
	
	Schema string `json:"schema,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	
	Timestamp time.Time `json:"timestamp"`
	TimestampUnix uint64 `json:"timestamp_unix"`
	
	Node string `json:"node,omitempty"`
	Service string `json:"service,omitempty"`
	Type string `json:"type,omitempty"`
	
	Level string `json:"level,omitempty"`
	LevelUnix int8 `json:"level_unix,omitempty"`
	
	Fields map[string]interface{} `json:"fields"`
}


const SyslogCollectorType = "syslog"
const SyslogMessageMetaDataSchema = SyslogCollectorType + ":" + "20181020a"




type HttpMessageMetaData struct {
	
	Schema string `json:"schema,omitempty"`
	
	Protocol string `json:"protocol,omitempty"`
	Url string `json:"url,omitempty"`
	UrlRaw string `json:"url_raw,omitempty"`
	
	Host string `json:"host,omitempty"`
	Method string `json:"method,omitempty"`
	Path string `json:"path,omitempty"`
	Query map[string][]string `json:"query,omitempty"`
	QueryRaw string `json:"query_raw,omitempty"`
	Headers HttpMessageHeaders `json:"headers,omitempty"`
	Trailers HttpMessageHeaders `json:"trailers,omitempty"`
	RemoteIp string `json:"remote_ip,omitempty"`
	RemotePort uint16 `json:"remote_port,omitempty"`
	
	ContentType string `json:"content_type,omitempty"`
	ContentTypeParameters map[string]string `json:"content_type_parameters,omitempty"`
	ContentEncoding string `json:"content_encoding,omitempty"`
	ContentLength int64 `json:"content_length,omitempty"`
	
	TransferEncoding HttpMessageHeaderValue `json:"transfer_encoding,omitempty"`
}


type HttpMessageHeaders map[string]HttpMessageHeaderValue
type HttpMessageHeaderValue interface{}


const HttpCollectorType = "http"
const HttpMessageMetaDataSchema = HttpCollectorType + ":" + "20181020a"




type MqttMessageMetaData struct {
	
	Schema string `json:"schema,omitempty"`
	Topic string `json:"topic,omitempty"`
}


const MqttCollectorType = "mqtt"
const MqttMessageMetaDataSchema = MqttCollectorType + ":" + "20181020a"


