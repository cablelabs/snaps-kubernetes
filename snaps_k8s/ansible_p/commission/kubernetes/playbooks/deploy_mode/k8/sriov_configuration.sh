#!/bin/bash
#* Copyright 2017 ARICENT HOLDINGS LUXEMBOURG SARL and Cable Television
# Laboratories, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script is responsible for deploying Aricent_Iaas environments and
# Kubernetes Services
INTERFACE=$1
echo "Start Script"
echo $INTERFACE
files=`find /sys/devices/ -name sriov_numvfs`;
echo $files
bus=`for i in ${files[@]}; do echo $i | awk -F "/" '{print $(NF-1)}' | awk -F "0000:" '{print $NF}'; done`;
echo "Bus info"
echo $bus
values=`for i in ${bus[@]}; do lspci -vvs $i | grep -A 20 "Single Root" | grep "Initial VFs" | awk -F "Initial VFs:" '{print $2}' | awk -F "," '{print $1}'| awk -F " " '{print $1}'; done`;
echo "values"
echo $values
#for index in ${!files[*]}; do echo $((${values[$index]}-1)) > ${files[$index]}; done #
k=0
for index in $files
do  
    echo $index
    var[c++]=$index
    
done    

echo ${var[5]};
awk '!/exit/' /etc/rc.local > temp && mv temp /etc/rc.local
awk '!/pci/' /etc/rc.local > temp && mv temp /etc/rc.local
for i  in $values
do 
       j=1
       temp=$(expr $i - $j)
       echo "Value is, file name is ", $temp, ${var[$k]}
       echo "echo '$temp' > ${var[$k]} ">>/etc/rc.local
       echo
       echo $temp>>${var[$k]}
       k=$((k+1))
done
echo "ip link set $INTERFACE up">>/etc/rc.local
echo "exit 0 ">>/etc/rc.local
chmod 777 /etc/rc.local
for i in $bus
do
    intf=`dmesg | grep renamed | grep $i | awk -F " " '{print $5}'|awk -F ":" '{print $1}'` 

    if [ "$intf" = "$INTERFACE" ];
    then
       echo "SRIOV enabled on intefce",$intf
       ip link set $intf up 
       break;
    else
       echo "SRIOV NOT enabled on provided Interface"
    fi
done
