{{- define "player.ns" -}}
{{ printf "team-%s" .Values.playerName | quote }}
{{- end -}}
