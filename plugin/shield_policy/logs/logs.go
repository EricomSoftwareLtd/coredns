package logs

import (
	"encoding/json"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Loggable interface {
	LogFields() []zap.Field
}

type CustomLogger struct {
	zap.Logger
}

var hostname, _ = os.Hostname()
var pid = os.Getpid()

var implicitReportFields = []zap.Field{
	zap.String("logType", "report"),
	zap.String("name", "Report"),
}

func (logger *CustomLogger) Report(msg string, fields ...zap.Field) {
	logger.Info(msg, append(fields, implicitReportFields...)...)
}

func (logger *CustomLogger) ReportObject(msg string, data Loggable) {
	logger.Report(msg, data.LogFields()...)
}

func New() *CustomLogger {
	// TODO set level from consul
	rawJSON := []byte(`{
		"level": "info",
		"encoding": "json",
		"outputPaths": ["stdout"],
		"errorOutputPaths": ["stdout"],
		"encoderConfig": {
		  "messageKey": "msg",
		  "levelKey": "level",
		  "timeKey": "time"
		}
	  }`)

	var cfg zap.Config
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		panic(err)
	}
	cfg.EncoderConfig.EncodeLevel = encodeLevelNumeric
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	logger := zap.Must(cfg.Build())
	logger = logger.With(
		zap.String("hostname", hostname),
		zap.Int("pid", pid),
	)
	shieldLogger := &CustomLogger{*logger}
	defer logger.Sync()

	return shieldLogger
}

func encodeLevelNumeric(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	switch level {
	case zapcore.DebugLevel:
		enc.AppendInt(20)
	case zapcore.InfoLevel:
		enc.AppendInt(30)
	case zapcore.WarnLevel:
		enc.AppendInt(40)
	case zapcore.ErrorLevel:
		enc.AppendInt(50)
	case zapcore.DPanicLevel:
		enc.AppendInt(60)
	case zapcore.PanicLevel:
		enc.AppendInt(60)
	case zapcore.FatalLevel:
		enc.AppendInt(60)
	default:
		enc.AppendInt(60)
	}
}
