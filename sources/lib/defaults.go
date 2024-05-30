

package lib


import "time"




const DefaultInputSyslogEnabled = false
const DefaultInputSyslogIdentifier = ""
const DefaultInputSyslogListenTcp = ""
const DefaultInputSyslogListenUdp = ""
const DefaultInputSyslogListenUnix = ""
const DefaultInputSyslogTimeout = 6 * time.Second
const DefaultInputSyslogProtocol = "rfc3164"
const DefaultInputSyslogParseJson = false
const DefaultInputSyslogParseXml = false
const DefaultInputSyslogDebug = false

const DefaultInputHttpEnabled = false
const DefaultInputHttpIdentifier = ""
const DefaultInputHttpListenTcp = ""
const DefaultInputHttpTimeout = 6 * time.Second
const DefaultInputHttpAllowedPath = ""
const DefaultInputHttpParseJson = false
const DefaultInputHttpParseXml = false
const DefaultInputHttpDebug = false

const DefaultInputMqttEnabled = false
const DefaultInputMqttIdentifier = ""
const DefaultInputMqttConnectTcp = ""
const DefaultInputMqttTopic = ""
const DefaultInputMqttTopicIgnore = ""
const DefaultInputMqttClient = ""
const DefaultInputMqttUsername = ""
const DefaultInputMqttPassword = ""
const DefaultInputMqttCleanSession = false
const DefaultInputMqttKeepAlive = 30 * time.Second
const DefaultInputMqttPing = 30 * time.Second
const DefaultInputMqttRetry = 1 * time.Second
const DefaultInputMqttParseJson = false
const DefaultInputMqttParseXml = false
const DefaultInputMqttDebug = false

const DefaultOutputStdoutEnabled = false
const DefaultOutputStdoutBufferSize = 16 * 1024
const DefaultOutputStdoutJsonPretty = true
const DefaultOutputStdoutJsonSequence = false
const DefaultOutputStdoutFlush = true
const DefaultOutputStdoutQueueSize = 16 * 1024
const DefaultOutputStdoutDebug = false

const DefaultOutputFileEnabled = false
const DefaultOutputFileCurrentStorePath = ""
const DefaultOutputFileCurrentSymlinkPath = ""
const DefaultOutputFileArchivedStorePath = ""
const DefaultOutputFileArchivedCompress = ""
const DefaultOutputFileArchivedCompressLevel = 9
const DefaultOutputFileCurrentPrefix = ""
const DefaultOutputFileArchivedPrefix = ""
const DefaultOutputFileCurrentSuffix = ".json-stream"
const DefaultOutputFileArchivedSuffix = ".json-stream"
const DefaultOutputFileCurrentTimestamp = "2006-01-02"
const DefaultOutputFileArchivedTimestamp = "2006-01/2006-01-02-15-04-05"
const DefaultOutputFileRotateInterval = 1 * time.Hour
const DefaultOutputFileRotateCounter = 16 * 1024
const DefaultOutputFileBufferSize = 16 * 1024
const DefaultOutputFileJsonPretty = false
const DefaultOutputFileJsonSequence = true
const DefaultOutputFileFlush = false
const DefaultOutputFileFolderMode = 0750
const DefaultOutputFileFileMode = 0640
const DefaultOutputFileQueueSize = 16 * 1024
const DefaultOutputFileDebug = false
const DefaultOutputFileTickerInterval = 6 * time.Second  //  NOTE:  internal

const DefaultOutputMqttEnabled = false
const DefaultOutputMqttConnectTcp = ""
const DefaultOutputMqttTopic = ""
const DefaultOutputMqttTopicSuffix = ""
const DefaultOutputMqttClient = ""
const DefaultOutputMqttUsername = ""
const DefaultOutputMqttPassword = ""
const DefaultOutputMqttCleanSession = false
const DefaultOutputMqttKeepAlive = 30 * time.Second
const DefaultOutputMqttPing = 30 * time.Second
const DefaultOutputMqttRetry = 1 * time.Second
const DefaultOutputMqttQueueSize = 16 * 1024
const DefaultOutputMqttDebug = false


const DefaultDequeueReportInterval = 60 * time.Second
const DefaultDequeueReportCounter = 1000
const DefaultDequeueDebug = false
const DefaultDequeueTickerInterval = 6 * time.Second  //  NOTE:  internal

const DefaultParserMessageRaw = true
const DefaultParserMessageSha256 = true
const DefaultParserExternalReplace = false
const DefaultParserDebug = false

const DefaultMessagesQueueSize = 16 * 1024
const DefaultSignalsQueueSize = 16
const DefaultGlobalDebug = false


