use crate::actions;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screen {
    Dashboard,
    Setup(SetupPhase),
    ClientCreate,
    ClientList,
    Service,
    Logs,
    Help,
    Confirm(ConfirmAction),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupPhase {
    Welcome,
    Keys,
    Config,
    Service,
    Firewall,
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmAction {
    Restart,
    Stop,
    #[allow(dead_code)]
    RemoveClient(String),
}

#[derive(Debug, Clone)]
pub struct PeerRow {
    pub name: String,
    pub ip: String,
    pub public_key: String,
    pub keepalive: String,
}

#[derive(Debug, Clone)]
pub struct ClientRow {
    pub name: String,
    pub ip: String,
    pub public_key: String,
    pub created: String,
}

pub struct App {
    pub screen: Screen,
    pub prev_screen: Option<Screen>,
    pub should_quit: bool,

    // server state
    pub server_running: bool,
    pub server_pid: Option<u32>,
    pub interface: String,
    pub port: u16,
    pub public_key: String,

    // data
    pub peers: Vec<PeerRow>,
    pub clients: Vec<ClientRow>,
    pub logs: Vec<String>,
    pub log_scroll: u16,

    // client create form
    pub input_name: String,
    pub input_endpoint: String,
    pub input_field: usize, // 0=name, 1=endpoint

    // setup
    pub setup_log: Vec<String>,

    // service manager
    pub service_info: Option<actions::system::ServiceInfo>,
    pub service_log: Vec<String>,

    // status message (bottom bar)
    pub status_msg: String,

    // system info
    pub sys: actions::system::System,
}

impl App {
    pub fn new() -> Self {
        let sys = actions::system::System::detect();
        let iface = sys.default_interface().to_owned();

        Self {
            screen: Screen::Dashboard,
            prev_screen: None,
            should_quit: false,
            server_running: false,
            server_pid: None,
            interface: iface,
            port: 51820,
            public_key: String::new(),
            peers: Vec::new(),
            clients: Vec::new(),
            logs: Vec::new(),
            log_scroll: 0,
            input_name: String::new(),
            input_endpoint: String::new(),
            input_field: 0,
            setup_log: Vec::new(),
            service_info: None,
            service_log: Vec::new(),
            status_msg: String::new(),
            sys,
        }
    }

    pub fn refresh(&mut self) {
        // refresh server status
        if let Ok(info) = actions::server::status(&self.sys) {
            self.server_running = info.contains("running");
            if let Some(pid_str) = info.split("pid ").nth(1) {
                self.server_pid = pid_str
                    .split(|c: char| !c.is_ascii_digit())
                    .next()
                    .and_then(|s| s.parse().ok());
            }
        }

        // refresh public key
        if let Ok(pk) = actions::keys::server_public_key() {
            self.public_key = pk;
        }

        // refresh peers
        if let Ok(peers) = actions::config::list_peers() {
            self.peers = peers
                .into_iter()
                .map(|p| PeerRow {
                    name: p.comment,
                    ip: p.allowed_ips,
                    public_key: p.public_key,
                    keepalive: p.keepalive,
                })
                .collect();
        }

        // refresh config
        if let Ok(cfg) = actions::config::load_server_config() {
            self.interface = cfg.interface;
            self.port = cfg.port;
        }

        // refresh clients
        if let Ok(clients) = actions::config::list_clients() {
            self.clients = clients
                .into_iter()
                .map(|c| ClientRow {
                    name: c.name,
                    ip: c.ip,
                    public_key: c.public_key,
                    created: c.created,
                })
                .collect();
        }
    }

    pub fn push_log(&mut self, msg: &str) {
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        self.logs.push(format!("[{ts}] {msg}"));
        // keep last 500 lines
        if self.logs.len() > 500 {
            self.logs.drain(..self.logs.len() - 500);
        }
    }

    pub fn set_status(&mut self, msg: &str) {
        self.status_msg = msg.to_owned();
    }

    pub fn refresh_service(&mut self) {
        self.service_info =
            Some(actions::system::service_status(&self.sys, &self.interface));
    }

    pub fn push_service_log(&mut self, msg: &str) {
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        self.service_log.push(format!("[{ts}] {msg}"));
    }

    pub fn go_to(&mut self, screen: Screen) {
        self.prev_screen = Some(self.screen.clone());
        self.screen = screen;
    }

    pub fn go_back(&mut self) {
        if let Some(prev) = self.prev_screen.take() {
            self.screen = prev;
        } else {
            self.screen = Screen::Dashboard;
        }
    }
}
