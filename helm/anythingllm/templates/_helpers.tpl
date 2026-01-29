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

{{- define "anythingllm.hasSecretEnv" -}}
{{- $flags := dict "value" false -}}
{{- range $k, $v := .Values.secretEnv -}}
{{- if $v -}}
{{- $_ := set $flags "value" true -}}
{{- end -}}
{{- end -}}
{{- $flags.value -}}
{{- end -}}
