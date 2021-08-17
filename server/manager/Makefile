install:
	rm -rf /opt/Elkeid_Manager
	cp -r . /opt/Elkeid_Manager
	chmod +x /opt/Elkeid_Manager/manager
	rm -f /etc/systemd/system/elkeid_manager.service
	cp /opt/Elkeid_Manager/elkeid_manager.service /etc/systemd/system/elkeid_manager.service

	systemctl daemon-reload
	echo "Install Elkeid Manager Success"

update:
	systemctl stop elkeid_manager.service
	rm /opt/Elkeid_Manager/manager
	cp ./manager /opt/Elkeid_Manager/
	systemctl start elkeid_manager.service

clean:
	systemctl stop elkeid_manager.service
	systemctl disable elkeid_manager.service
	rm -f  /etc/systemd/system/elkeid_manager.service
	rm -rf /opt/Elkeid_Manager/
	systemctl daemon-reload
