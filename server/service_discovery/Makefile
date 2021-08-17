install:
	rm -rf /opt/Elkeid_SD
	cp -r . /opt/Elkeid_SD
	chmod +x /opt/Elkeid_SD/sd
	rm -f /etc/systemd/system/elkeid_sd.service
	cp /opt/Elkeid_SD/elkeid_sd.service /etc/systemd/system/elkeid_sd.service

	systemctl daemon-reload
	echo "Install Elkeid Service Discovery Success"

update:
	systemctl stop elkeid_sd.service
	rm /opt/Elkeid_SD/sd
	cp ./sd /opt/Elkeid_SD/
	systemctl start elkeid_sd.service

clean:
	systemctl stop elkeid_sd.service
	systemctl disable elkeid_sd.service
	rm -f  /etc/systemd/system/elkeid_sd.service
	rm -rf /opt/Elkeid_SD/
	systemctl daemon-reload
