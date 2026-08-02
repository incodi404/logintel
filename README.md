# Logintel Agent

Logintel is a open source security monitoring and control system. This is used for kernel-level monitoring, command-and-control, alert generating based on rules, storing and visualizing logs efficiently.

Logintel Agent is a Golang-based endpoint security agent. It collects events from kernel and streams those events. It is capable of collecting command execution events, network events, file operation events and systemd services status. It uses eBPF to capture most of the events directly from the kernel. The agent is able to executes commands on the system. It has command-and-control system within it that allows the agent to work as an Incident Response system.

---

#### The system is still under development and getting better day by day. The first release of the system will be within October, 2026.
