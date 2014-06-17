#!/bin/bash

OUI=$(echo ${1//[:.- ]/} | tr "[a-f]" "[A-F]" | egrep -o "^[0-9A-F]{6}")

##Very slow (use daily updated list)
#lynx -dump http://standards.ieee.org/regauth/oui/oui.txt | grep $OUI

cat oui.txt | grep $OUI
