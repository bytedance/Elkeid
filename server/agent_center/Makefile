install:
	rm -rf /opt/Elkeid_AC
	cp -r . /opt/Elkeid_AC
	chmod +x /opt/Elkeid_AC/agent_center
	rm -f /etc/systemd/system/elkeid_ac.service
	cp /opt/Elkeid_AC/elkeid_ac.service /etc/systemd/system/elkeid_ac.service

	systemctl daemon-reload
	echo "Install Elkeid AgentCenter Success"

update:
	systemctl stop elkeid_ac.service
	rm /opt/Elkeid_AC/agent_center
	cp ./agent_center /opt/Elkeid_AC/
	systemctl start elkeid_ac.service

clean:
	systemctl stop elkeid_ac.service
	systemctl disable elkeid_ac.service
	rm -f  /etc/systemd/system/elkeid_ac.service
	rm -rf /opt/Elkeid_AC/
	systemctl daemon-reload
