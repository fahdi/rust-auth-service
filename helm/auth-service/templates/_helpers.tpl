{{/*
Expand the name of the chart.
*/}}
{{- define "auth-service.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "auth-service.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "auth-service.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "auth-service.labels" -}}
helm.sh/chart: {{ include "auth-service.chart" . }}
{{ include "auth-service.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "auth-service.selectorLabels" -}}
app.kubernetes.io/name: {{ include "auth-service.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "auth-service.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "auth-service.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Generate MongoDB URL
*/}}
{{- define "auth-service.mongodbUrl" -}}
{{- if .Values.mongodb.enabled }}
{{- $serviceName := printf "%s-mongodb" (include "auth-service.fullname" .) }}
{{- if .Values.mongodb.auth.enabled }}
mongodb://{{ .Values.mongodb.auth.username }}:{{ .Values.mongodb.auth.password }}@{{ $serviceName }}:27017/{{ .Values.mongodb.auth.database }}
{{- else }}
mongodb://{{ $serviceName }}:27017/{{ .Values.mongodb.auth.database }}
{{- end }}
{{- else }}
{{- .Values.secrets.mongodbUrl }}
{{- end }}
{{- end }}

{{/*
Generate Redis URL
*/}}
{{- define "auth-service.redisUrl" -}}
{{- if .Values.redis.enabled }}
{{- $serviceName := printf "%s-redis-master" (include "auth-service.fullname" .) }}
{{- if .Values.redis.auth.enabled }}
redis://:{{ .Values.redis.auth.password }}@{{ $serviceName }}:6379
{{- else }}
redis://{{ $serviceName }}:6379
{{- end }}
{{- else }}
{{- .Values.secrets.redisUrl }}
{{- end }}
{{- end }}

{{/*
Generate PostgreSQL URL
*/}}
{{- define "auth-service.postgresqlUrl" -}}
{{- if .Values.postgresql.enabled }}
{{- $serviceName := printf "%s-postgresql" (include "auth-service.fullname" .) }}
postgresql://{{ .Values.postgresql.auth.username }}:{{ .Values.postgresql.auth.password }}@{{ $serviceName }}:5432/{{ .Values.postgresql.auth.database }}
{{- else }}
{{- .Values.secrets.postgresqlUrl }}
{{- end }}
{{- end }}

{{/*
Validate required values
*/}}
{{- define "auth-service.validateValues" -}}
{{- if not .Values.secrets.jwtSecret }}
{{- fail "A valid JWT secret is required. Please set secrets.jwtSecret" }}
{{- end }}
{{- if and (not .Values.mongodb.enabled) (not .Values.postgresql.enabled) (not .Values.secrets.mongodbUrl) }}
{{- fail "Either enable a database (mongodb.enabled or postgresql.enabled) or provide a database URL" }}
{{- end }}
{{- end }}

{{/*
Generate database configuration based on enabled services
*/}}
{{- define "auth-service.databaseConfig" -}}
{{- if .Values.mongodb.enabled }}
type: mongodb
mongodb:
  url: {{ include "auth-service.mongodbUrl" . }}
  database: {{ .Values.mongodb.auth.database }}
  pool_size: {{ .Values.config.database.poolSize }}
  timeout: {{ .Values.config.database.timeout }}
{{- else if .Values.postgresql.enabled }}
type: postgresql
postgresql:
  url: {{ include "auth-service.postgresqlUrl" . }}
  pool_size: {{ .Values.config.database.poolSize }}
  timeout: {{ .Values.config.database.timeout }}
{{- else }}
type: {{ .Values.config.database.type }}
{{- end }}
{{- end }}

{{/*
Generate cache configuration
*/}}
{{- define "auth-service.cacheConfig" -}}
{{- if .Values.redis.enabled }}
redis:
  url: {{ include "auth-service.redisUrl" . }}
  pool_size: 10
  timeout: 5
memory:
  max_size: {{ .Values.config.cache.maxSize }}
  ttl: {{ .Values.config.cache.ttl }}
{{- else }}
memory:
  max_size: {{ .Values.config.cache.maxSize }}
  ttl: {{ .Values.config.cache.ttl }}
{{- end }}
{{- end }}