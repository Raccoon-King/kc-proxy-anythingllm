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

{{- define "proxy.hasSecretEnv" -}}
{{- $flags := dict "value" false -}}
{{- range $k, $v := .Values.secretEnv -}}
{{- if $v -}}
{{- $_ := set $flags "value" true -}}
{{- end -}}
{{- end -}}
{{- $flags.value -}}
{{- end -}}
