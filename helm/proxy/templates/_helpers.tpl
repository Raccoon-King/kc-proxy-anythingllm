{{- define "proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "proxy.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s" $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "proxy.labels" -}}
helm.sh/chart: {{ include "proxy.chart" . }}
app.kubernetes.io/name: {{ include "proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | default .Values.image.tag | quote }}
app.kubernetes.io/component: proxy
app.kubernetes.io/part-of: anythingllm-stack
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "proxy.hasSecretEnv" -}}
{{- if .Values.secretEnv -}}
{{- if gt (len .Values.secretEnv) 0 -}}
true
{{- end -}}
{{- end -}}
{{- end -}}
