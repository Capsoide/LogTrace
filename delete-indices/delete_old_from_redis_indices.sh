#!/bin/bash

ES_HOST="https://192.168.56.10:9200"
ES_USER="username"
ES_PASS="password"

CUTOFF_DATE=$(date -d '3 days ago' +%Y-%m-%d)

echo "Rimuovo gli indici from-redis-* più vecchi di $CUTOFF_DATE"

INDICES=$(curl -s -u $ES_USER:$ES_PASS -k "$ES_HOST/_cat/indices/from-redis-*?h=index" | sort)

for INDEX in $INDICES; do
  #Conversione formato data da YYYY.MM.DD a YYYY-MM-DD
  IDX_DATE=$(echo $INDEX | sed -E 's/from-redis-([0-9]{4})\.([0-9]{2})\.([0-9]{2})/\1-\2-\3/')

  IDX_TS=$(date -d "$IDX_DATE" +%s 2>/dev/null)
  CUTOFF_TS=$(date -d "$CUTOFF_DATE" +%s)

  if [ -z "$IDX_TS" ]; then
    echo "Formato data non valido per indice $INDEX, salto."
    continue
  fi

  if [ $IDX_TS -lt $CUTOFF_TS ]; then
    echo "Elimino indice $INDEX (data: $IDX_DATE)"
    curl -u $ES_USER:$ES_PASS -X DELETE "$ES_HOST/$INDEX" -k
  else
    echo "Mantengo indice $INDEX (data: $IDX_DATE)"
  fi
done
