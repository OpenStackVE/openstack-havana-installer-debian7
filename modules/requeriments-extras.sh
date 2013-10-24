#!/bin/bash
#
# Instalador desatendido para Openstack Havana sobre DEBIAN
# Reynaldo R. Martinez P.
# E-Mail: TigerLinux@Gmail.com
# Octubre del 2013
#
# Script de instalacion y preparacion de pre-requisitos extras
#

PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin

if [ -f ./configs/main-config.rc ]
then
	source ./configs/main-config.rc
	mkdir -p /etc/openstack-control-script-config
else
	echo "No puedo acceder a mi archivo de configuración"
	echo "Revise que esté ejecutando el instalador/módulos en el directorio correcto"
	echo "Abortando !!!!."
	echo ""
	exit 0
fi

if [ -f /etc/openstack-control-script-config/requeriments-extras-installed ]
then
	echo ""
	echo "Requisitos extras previamente instalados"
	echo ""
	exit 0
fi

echo ""
echo "Instalando paquetes base de Python para manejo de Bases de Datos"
echo ""
aptitude -y install python-sqlalchemy python-sqlalchemy-ext \
	python-psycopg2 python-mysqldb python-keystoneclient python-keystone \
	python-argparse

initiallist='
	python-keystoneclient
	python-sqlalchemy
	python-keystoneclient
	python-psycopg2
	python-mysqldb
'
	
for mypack in $initiallist
do
	testpackinstalled=`dpkg -l $mypack 2>/dev/null|tail -n 1|grep -ci ^ii`
	if [ $testpackinstalled == "1" ]
	then
		echo "Paquete $mypack verificado"
	else
		echo "El paquete $mypack no aparece instalado - abortando instalación"
		exit 0
	fi
done

date > /etc/openstack-control-script-config/requeriments-extras-installed

echo ""
echo "Listo"
echo ""
