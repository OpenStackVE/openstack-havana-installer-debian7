#!/bin/bash
#
# Instalador desatendido para Openstack Havana sobre DEBIAN
# Reynaldo R. Martinez P.
# E-Mail: TigerLinux@gmail.com
# Octubre del 2013
#
# Script de instalacion y preparacion de swift
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

if [ -f /etc/openstack-control-script-config/db-installed ]
then
	echo ""
	echo "Proceso de BD verificado - continuando"
	echo ""
else
	echo ""
	echo "Este módulo depende de que el proceso de base de datos"
	echo "haya sido exitoso, pero aparentemente no lo fue"
	echo "Abortando el módulo"
	echo ""
	exit 0
fi

if [ -f /etc/openstack-control-script-config/keystone-installed ]
then
	echo ""
	echo "Proceso principal de Keystone verificado - continuando"
	echo ""
else
	echo ""
	echo "Este módulo depende del proceso principal de keystone"
	echo "pero no se pudo verificar que dicho proceso haya sido"
	echo "completado exitosamente - se abortará el proceso"
	echo ""
	exit 0
fi

if [ -f /etc/openstack-control-script-config/swift-installed ]
then
	echo ""
	echo "Este módulo ya fue ejecutado de manera exitosa - saliendo"
	echo ""
	exit 0
fi

echo ""
echo "Preparando recurso de filesystems"
echo ""

if [ ! -d "/srv/node" ]
then
	rm -f /etc/openstack-control-script-config/swift
	echo ""
	echo "ALERTA !. No existe el recurso de discos para swift - Abortando el"
	echo "resto de la instalación de swift"
	echo "Corrija la situación y vuelva a intentar ejecutar el módulo de"
	echo "instalación de swift"
	echo "El resto de la instalación de OpenStack continuará de manera normal,"
	echo "pero sin swift"
	echo "Dormiré por 10 segundos para que lea este mensaje"
	echo ""
	sleep 10
	exit 0
fi

checkdevice=`mount|awk '{print $3}'|grep -c ^/srv/node/$swiftdevice$`

case $checkdevice in
1)
	echo ""
	echo "Punto de montaje /srv/node/$swiftdevice verificado"
	echo "continuando con la instalación"
	echo ""
	;;
0)
	rm -f /etc/openstack-control-script-config/swift
	rm -f /etc/openstack-control-script-config/swift-installed
	echo ""
	echo "ALERTA !. No existe el recurso de discos para swift - Abortando el"
	echo "resto de la instalación de swift"
	echo "Corrija la situación y vuelva a intentar ejecutar el módulo de"
	echo "instalación de swift"
	echo "El resto de la instalación de OpenStack continuará de manera normal,"
	echo "pero sin swift"
	echo "Dormiré por 10 segundos para que lea este mensaje"
	echo ""
	sleep 10
	echo ""
	exit 0
	;;
esac

if [ $cleanupdeviceatinstall == "yes" ]
then
	rm -rf /srv/node/$swiftdevice/accounts
	rm -rf /srv/node/$swiftdevice/containers
	rm -rf /srv/node/$swiftdevice/objects
	rm -rf /srv/node/$swiftdevice/tmp
fi

echo ""
echo "Instalando paquetes para Swift"

aptitude -y install swift swift-account swift-container swift-doc swift-object swift-plugin-s3 swift-proxy memcached

cp -v ./libs/swift/* /etc/swift/

echo "Listo"
echo ""

source $keystone_admin_rc_file

iptables -A INPUT -p tcp -m multiport --dports 6000,6001,6002,873 -j ACCEPT
/etc/init.d/iptables-persistent save

chown -R swift:swift /srv/node/

echo ""
echo "Configurando Swift"
echo ""

mkdir -p /var/lib/keystone-signing-swift
chown swift:swift /var/lib/keystone-signing-swift

openstack-config --set /etc/swift/swift.conf swift-hash swift_hash_path_suffix $(openssl rand -hex 10)
# Ya no se necesita ???... esperando confirmación...
# openstack-config --set /etc/swift/swift.conf swift-hash swift_hash_path_prefix $(openssl rand -hex 10)

swiftworkers=`grep processor.\*: /proc/cpuinfo |wc -l`

openstack-config --set /etc/swift/object-server.conf DEFAULT bind_ip $swifthost
openstack-config --set /etc/swift/object-server.conf DEFAULT workers $swiftworkers
openstack-config --set /etc/swift/account-server.conf DEFAULT bind_ip $swifthost
openstack-config --set /etc/swift/account-server.conf DEFAULT workers $swiftworkers
openstack-config --set /etc/swift/container-server.conf DEFAULT bind_ip $swifthost
openstack-config --set /etc/swift/container-server.conf DEFAULT workers $swiftworkers

/etc/init.d/swift-account start
/etc/init.d/swift-account-auditor start
/etc/init.d/swift-account-reaper start
/etc/init.d/swift-account-replicator start

/etc/init.d/swift-container start
/etc/init.d/swift-container-auditor start
/etc/init.d/swift-container-replicator start
/etc/init.d/swift-container-updater start

/etc/init.d/swift-object start
/etc/init.d/swift-object-auditor start
/etc/init.d/swift-object-replicator start
/etc/init.d/swift-object-updater start

chkconfig swift-account on
chkconfig swift-account-auditor on
chkconfig swift-account-reaper on
chkconfig swift-account-replicator on

chkconfig swift-container on
chkconfig swift-container-auditor on
chkconfig swift-container-replicator on
chkconfig swift-container-updater on

chkconfig swift-object on
chkconfig swift-object-auditor on
chkconfig swift-object-replicator on
chkconfig swift-object-updater on

/etc/init.d/swift-account restart
/etc/init.d/swift-account-auditor restart
/etc/init.d/swift-account-reaper restart
/etc/init.d/swift-account-replicator restart

/etc/init.d/swift-container restart
/etc/init.d/swift-container-auditor restart
/etc/init.d/swift-container-replicator restart
/etc/init.d/swift-container-updater restart

/etc/init.d/swift-object restart
/etc/init.d/swift-object-auditor restart
/etc/init.d/swift-object-replicator restart
/etc/init.d/swift-object-updater restart

openstack-config --set /etc/swift/proxy-server.conf DEFAULT bind_port 8080
openstack-config --set /etc/swift/proxy-server.conf DEFAULT workers $swiftworkers
openstack-config --set /etc/swift/proxy-server.conf "pipeline:main" pipeline "healthcheck cache authtoken keystoneauth proxy-server"
openstack-config --set /etc/swift/proxy-server.conf "app:proxy-server" use "egg:swift#proxy"
openstack-config --set /etc/swift/proxy-server.conf "app:proxy-server" allow_account_management true
openstack-config --set /etc/swift/proxy-server.conf "app:proxy-server" account_autocreate true
openstack-config --set /etc/swift/proxy-server.conf "filter:keystoneauth" use "egg:swift#keystoneauth"
openstack-config --set /etc/swift/proxy-server.conf "filter:keystoneauth" operator_roles "Member,admin,swiftoperator"
openstack-config --set /etc/swift/proxy-server.conf "filter:authtoken" paste.filter_factory "keystoneclient.middleware.auth_token:filter_factory"
openstack-config --set /etc/swift/proxy-server.conf "filter:authtoken" delay_auth_decision true
openstack-config --set /etc/swift/proxy-server.conf "filter:authtoken" admin_token $SERVICE_TOKEN
openstack-config --set /etc/swift/proxy-server.conf "filter:authtoken" auth_token $SERVICE_TOKEN
openstack-config --set /etc/swift/proxy-server.conf "filter:authtoken" admin_tenant_name $keystoneservicestenant
openstack-config --set /etc/swift/proxy-server.conf "filter:authtoken" admin_user $swiftuser
openstack-config --set /etc/swift/proxy-server.conf "filter:authtoken" admin_password $swiftpass
openstack-config --set /etc/swift/proxy-server.conf "filter:authtoken" auth_host $keystonehost
openstack-config --set /etc/swift/proxy-server.conf "filter:authtoken" auth_port 35357
openstack-config --set /etc/swift/proxy-server.conf "filter:authtoken" auth_protocol http
openstack-config --set /etc/swift/proxy-server.conf "filter:authtoken" signing_dir /var/lib/keystone-signing-swift
openstack-config --set /etc/swift/proxy-server.conf "filter:cache" use "egg:swift#memcache"
openstack-config --set /etc/swift/proxy-server.conf "filter:catch_errors" use "egg:swift#catch_errors"
openstack-config --set /etc/swift/proxy-server.conf "filter:healthcheck" use "egg:swift#healthcheck"

mkdir -p /var/lib/keystone-signing-swift
chown -R swift:swift /var/lib/keystone-signing-swift


if [ $ceilometerinstall == "yes" ]
then
        openstack-config --set /etc/swift/proxy-server.conf filter:ceilometer use "egg:ceilometer#swift"
fi

/etc/init.d/memcached start
/etc/init.d/swift-proxy start


swift-ring-builder /etc/swift/object.builder create $partition_power $replica_count $partition_min_hours
swift-ring-builder /etc/swift/container.builder create $partition_power $replica_count $partition_min_hours
swift-ring-builder /etc/swift/account.builder create $partition_power $replica_count $partition_min_hours

swift-ring-builder /etc/swift/account.builder add z$swiftfirstzone-$swifthost:6002/$swiftdevice $partition_count
swift-ring-builder /etc/swift/container.builder add z$swiftfirstzone-$swifthost:6001/$swiftdevice $partition_count
swift-ring-builder /etc/swift/object.builder add z$swiftfirstzone-$swifthost:6000/$swiftdevice $partition_count

swift-ring-builder /etc/swift/account.builder rebalance
swift-ring-builder /etc/swift/container.builder rebalance
swift-ring-builder /etc/swift/object.builder rebalance


chkconfig memcached on
chkconfig swift-proxy on

sync
/etc/init.d/swift-proxy stop
/etc/init.d/swift-proxy start
sync

iptables -A INPUT -p tcp -m multiport --dports 8080 -j ACCEPT
/etc/init.d/iptables-persistent save

testswift=`dpkg -l swift-proxy 2>/dev/null|tail -n 1|grep -ci ^ii`
if [ $testswift == "0" ]
then
	echo ""
	echo "Falló la instalación de swift - abortando el resto de la instalación"
	echo ""
	rm -f /etc/openstack-control-script-config/swift
	rm -f /etc/openstack-control-script-config/swift-installed
	exit 0
else
	date > /etc/openstack-control-script-config/swift-installed
	date > /etc/openstack-control-script-config/swift
fi

echo ""
echo "Instalación básica de SWIFT terminada"
echo ""






