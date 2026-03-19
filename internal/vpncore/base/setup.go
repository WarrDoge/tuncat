package base

func Setup(cfg *ClientConfig) {
	if cfg == nil {
		cfg = NewClientConfig()
	}
	InitLog(cfg)
}
