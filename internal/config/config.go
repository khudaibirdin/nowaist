package config

import "github.com/spf13/viper"

type Config struct {
	DataProviderURL string `mapstructure:"DATA_PROVIDER_URL"`
	HTTPPort        string `mapstructure:"HTTP_PORT"`
	JWTSecret       string `mapstructure:"JWT_SECRET"`
}

func New(envPath string) (*Config, error) {
	viper.SetConfigFile(envPath)
	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}
	viper.AutomaticEnv()
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
