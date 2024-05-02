

package main


import "time"




const DefaultInputSyslogEnabled = false
const DefaultInputSyslogIdentifier = ""
const DefaultInputSyslogListenTcp = ""
const DefaultInputSyslogListenUdp = ""
const DefaultInputSyslogListenUnix = ""
const DefaultInputSyslogTimeout = 6 * time.Second
const DefaultInputSyslogFormat = "rfc3164"
const DefaultInputSyslogParseJson = false
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
const DefaultInputMqttClient = ""
const DefaultInputMqttUsername = ""
const DefaultInputMqttPassword = ""
const DefaultInputMqttKeepAlive = 30
const DefaultInputMqttCleanSession = false
const DefaultInputMqttParseJson = false
const DefaultInputMqttDebug = false

const DefaultOutputStdoutEnabled = true
const DefaultOutputStdoutJsonPretty = true
const DefaultOutputStdoutJsonSequence = false
const DefaultOutputStdoutFlush = false
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
const DefaultOutputFileMessages = 16 * 1024
const DefaultOutputFileTimeout = 1 * time.Hour
const DefaultOutputFileJsonPretty = false
const DefaultOutputFileJsonSequence = true
const DefaultOutputFileFlush = true
const DefaultOutputFileStoreMode = 0750
const DefaultOutputFileFileMode = 0640
const DefaultOutputFileTickerInterval = 6 * time.Second
const DefaultOutputFileQueueSize = 16 * 1024
const DefaultOutputFileDebug = false

const DefaultOutputBufferSize = 16 * 1024

const DefaultParserMessageRaw = true
const DefaultParserMessageSha256 = true
const DefaultParserExternalReplace = false
const DefaultParserDebug = false

const DefaultDequeueTickerInterval = 6 * time.Second
const DefaultDequeueReportInterval = 60 * time.Second
const DefaultDequeueReportCounter = 1000
const DefaultDequeueDebug = false

const DefaultMessagesQueueSize = 16 * 1024
const DefaultSignalsQueueSize = 16
const DefaultGlobalDebug = false


