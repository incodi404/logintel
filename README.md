# Logintel Agent

Logintel is a open source security monitoring and control system. This is used for kernel-level monitoring, command-and-control, alert generating based on rules, storing and visualizing logs efficiently.

Logintel Agent is a Golang-based endpoint security agent, built for Linux. It collects events from kernel and streams those events. It is capable of collecting command execution events, network events, file operation events and systemd services status. It uses eBPF to capture most of the events directly from the kernel. The agent is able to executes commands on the system. It has command-and-control system within it that allows the agent to work as an Incident Response system.<br>

#### The system is still under development and getting better day by day. The first release of the system will be within October, 2026.

## Agent Abilities

A detailed description of Logintel Agent about its abilities.

#### Command execution events capturing

The agent is able to capture each and every command that has been executed on the system. The successfully executed commands are logged differently and all types of command, whether successfully executed or not, are logged differently.

#### Networking events

It is capturing network events with 3 different scopes. The 3 scopes are -

- ##### TCP/UDP Connection's State Change

  Whenever a TCP/UDP connection changes its state, the event is captured. All the information regarding the connect (i.e, source IP address, destination IP address, source port, destination port, PID etc.) will be provided in the log.

- ##### New TCP/UDP Connection

  When the system initates a connection, the event is logged and all the information are captured.

- ##### TCP Binding
  When the `bind()` calls, the event is captured
