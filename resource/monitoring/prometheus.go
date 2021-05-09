package monitoring

import "fmt"

func (pm *PrometheusMonitoring) CountLogin(endpointName string, statusCode int, errorMsg string, latency float64) {
	pm.httpMonitoringCounter.WithLabelValues(endpointName, fmt.Sprintf("%d", statusCode), errorMsg).Inc()
	pm.httpMonitoringHistogram.WithLabelValues(endpointName, fmt.Sprintf("%d", statusCode), errorMsg).Observe(latency)
}
