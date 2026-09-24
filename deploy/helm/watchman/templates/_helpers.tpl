{{- define "watchman.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "watchman.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "watchman.labels" -}}
{{ include "watchman.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "watchman.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "watchman.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- required "serviceAccount.name is required when serviceAccount.create=false" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "watchman.secretName" -}}
{{- if .Values.secret.existingSecret -}}
{{- .Values.secret.existingSecret -}}
{{- else if .Values.secret.create -}}
{{- include "watchman.fullname" . -}}
{{- end -}}
{{- end -}}

{{- define "watchman.webhookSecretName" -}}
{{- .Values.webhook.existingSecret | default (printf "%s-webhook" (include "watchman.fullname" .)) -}}
{{- end -}}

{{- define "watchman.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- end -}}
{{- end -}}

{{/* POST /alert 허용 Host — 서비스 DNS 전 형태 + localhost + 추가분. 코드 기본값은
     agent-system 네임스페이스 전제라 다른 네임스페이스에선 반드시 이걸로 덮어야 한다. */}}
{{- define "watchman.writeHosts" -}}
{{- $svc := include "watchman.fullname" . -}}
{{- $ns := .Release.Namespace -}}
{{- $hosts := list "localhost" "127.0.0.1" "::1" $svc (printf "%s.%s" $svc $ns) (printf "%s.%s.svc" $svc $ns) (printf "%s.%s.svc.%s" $svc $ns .Values.clusterDomain) -}}
{{- concat $hosts .Values.extraWriteHosts | uniq | join "," -}}
{{- end -}}
