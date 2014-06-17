#!/bin/bash

while read p; do
  /bin/bash getOUI.sh $p
done < $1
