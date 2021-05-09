package monitoring

import "github.com/prometheus/client_golang/prometheus"

type PrometheusMonitoring struct {
	httpMonitoringCounter   *prometheus.CounterVec
	httpMonitoringHistogram *prometheus.HistogramVec
}

type IMonitoring interface {
	CountLogin(endpointName string, statuscode int, errorMsg string, latency float64)
}

func NewPrometheusMonitoring() IMonitoring {
	httpMonitoringCounter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_endpoints_monitoring",
			Help: "Http monitoring for account service",
		},
		[]string{"endpoint_name", "status_code", "errror"},
	)
	httpMonitoringHistogram := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "http_endpoints_latency",
			Help: "http Latency monitoring",
		},
		[]string{"endpoint_name", "status_code", "errror"},
	)

	prometheus.MustRegister(httpMonitoringCounter)
	prometheus.MustRegister(httpMonitoringHistogram)

	return &PrometheusMonitoring{
		httpMonitoringCounter:   httpMonitoringCounter,
		httpMonitoringHistogram: httpMonitoringHistogram,
	}
}
