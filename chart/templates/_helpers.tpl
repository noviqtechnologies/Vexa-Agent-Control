{{/*
Expand the name of the chart.
*/}}
{{- define "agentcontrol.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name (truncated at 63 chars).
*/}}
{{- define "agentcontrol.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart label
*/}}
{{- define "agentcontrol.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every resource in the chart.
*/}}
{{- define "agentcontrol.labels" -}}
helm.sh/chart: {{ include "agentcontrol.chart" . }}
{{ include "agentcontrol.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: agentcontrol
{{- end }}

{{/*
Selector labels (subset of common labels that must not change on upgrade).
*/}}
{{- define "agentcontrol.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentcontrol.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Operator-specific selector labels.
*/}}
{{- define "agentcontrol.operatorSelectorLabels" -}}
app.kubernetes.io/name: {{ include "agentcontrol.name" . }}-operator
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: operator
{{- end }}

{{/*
Gateway-specific selector labels. These are ALSO applied to the pod as
`agentcontrol.io/gateway: "true"` so the NetworkPolicy default selector matches.
*/}}
{{- define "agentcontrol.gatewaySelectorLabels" -}}
app.kubernetes.io/name: {{ include "agentcontrol.name" . }}-gateway
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: gateway
{{- end }}

{{/*
Service account name for the operator.
*/}}
{{- define "agentcontrol.operatorServiceAccountName" -}}
{{- printf "%s-operator" (include "agentcontrol.fullname" .) }}
{{- end }}

{{/*
Container image reference — falls back to Chart.AppVersion when tag is empty.
*/}}
{{- define "agentcontrol.operatorImage" -}}
{{- $tag := .Values.operator.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.operator.image.repository $tag -}}
{{- end }}

{{- define "agentcontrol.gatewayImage" -}}
{{- $tag := .Values.gateway.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.gateway.image.repository $tag -}}
{{- end }}

{{/*
Resolve the ConfigMap name that holds the gateway policy — either the
external one the user pointed at, or the chart-managed one.
*/}}
{{- define "agentcontrol.policyConfigMapName" -}}
{{- if .Values.gateway.policy.externalConfigMap -}}
{{- .Values.gateway.policy.externalConfigMap -}}
{{- else -}}
{{- printf "%s-gateway-policy" (include "agentcontrol.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
Resolve the TLS Secret name — either user-provided or chart-generated.
*/}}
{{- define "agentcontrol.tlsSecretName" -}}
{{- if .Values.gateway.tls.secretName -}}
{{- .Values.gateway.tls.secretName -}}
{{- else -}}
{{- printf "%s-gateway-tls" (include "agentcontrol.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
FR-23: Dashboard API selector labels.
*/}}
{{- define "agentcontrol.dashboardApiSelectorLabels" -}}
app.kubernetes.io/name: {{ include "agentcontrol.name" . }}-dashboard-api
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: dashboard-api
{{- end }}

{{/*
FR-23: Dashboard Frontend selector labels.
*/}}
{{- define "agentcontrol.dashboardFrontendSelectorLabels" -}}
app.kubernetes.io/name: {{ include "agentcontrol.name" . }}-dashboard-frontend
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: dashboard-frontend
{{- end }}

{{/*
FR-23: Dashboard DB selector labels.
*/}}
{{- define "agentcontrol.dashboardDbSelectorLabels" -}}
app.kubernetes.io/name: {{ include "agentcontrol.name" . }}-dashboard-db
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: dashboard-db
{{- end }}

{{/*
FR-23: Dashboard API image reference.
*/}}
{{- define "agentcontrol.dashboardApiImage" -}}
{{- $tag := .Values.dashboardApi.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.dashboardApi.image.repository $tag -}}
{{- end }}

{{/*
FR-23: Dashboard Frontend image reference.
*/}}
{{- define "agentcontrol.dashboardFrontendImage" -}}
{{- $tag := .Values.dashboardFrontend.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.dashboardFrontend.image.repository $tag -}}
{{- end }}

{{/*
FR-23: Dashboard DB image reference.
*/}}
{{- define "agentcontrol.dashboardDbImage" -}}
{{- printf "%s:%s" .Values.dashboardDb.image.repository .Values.dashboardDb.image.tag -}}
{{- end }}
