{{- define "anythingllm.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "anythingllm.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s" $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "anythingllm.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "anythingllm.labels" -}}
helm.sh/chart: {{ include "anythingllm.chart" . }}
app.kubernetes.io/name: {{ include "anythingllm.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | default .Values.image.tag | quote }}
app.kubernetes.io/component: backend
app.kubernetes.io/part-of: anythingllm-stack
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "anythingllm.selectorLabels" -}}
app.kubernetes.io/name: {{ include "anythingllm.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "anythingllm.hasSecretEnv" -}}
{{- if .Values.secretEnv -}}
{{- if gt (len .Values.secretEnv) 0 -}}
true
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Generate JWT_SECRET - use provided value or generate random
*/}}
{{- define "anythingllm.jwtSecret" -}}
{{- if .Values.env.JWT_SECRET -}}
{{- .Values.env.JWT_SECRET -}}
{{- else -}}
{{- randAlphaNum 64 -}}
{{- end -}}
{{- end -}}
