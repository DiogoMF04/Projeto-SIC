# common/gui.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import json
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime
import asyncio
from collections import deque

class NetworkGUI:
    """GUI base para visualização da rede"""

    def __init__(self, title: str, is_sink: bool = False):
        self.is_sink = is_sink
        self.root = tk.Tk()
        self.root.title(title)
        self.root.geometry("1000x700")
        self.root.configure(bg='#f0f0f0')
        
        # Callbacks para interação com o nó/sink
        self.on_send_message: Optional[Callable] = None
        self.on_scan_network: Optional[Callable] = None
        self.on_disconnect: Optional[Callable] = None
        self.on_command: Optional[Callable] = None
        
        self._setup_styles()
        self._create_widgets()
        
        # Queue para updates thread-safe
        self.update_queue = deque()
        self.root.after(100, self._process_updates)

    def _setup_styles(self):
        """Configura estilos ttk"""
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Title.TLabel", font=("Helvetica", 16, "bold"))
        style.configure("Header.TLabel", font=("Helvetica", 12, "bold"))
        style.configure("Status.TLabel", font=("Helvetica", 10))
        style.configure("Action.TButton", font=("Helvetica", 10, "bold"))
        
        # Cores de status
        style.configure("Connected.TLabel", foreground="green")
        style.configure("Disconnected.TLabel", foreground="red")
        style.configure("Recovering.TLabel", foreground="orange")

    def _create_widgets(self):
        """Cria estrutura da GUI"""
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)

        # Título
        title_text = "🔷 SINK - Gateway IoT" if self.is_sink else "📡 IoT Node"
        ttk.Label(main_frame, text=title_text, style="Title.TLabel").grid(
            row=0, column=0, columnspan=3, pady=(0, 10))

        # Painel de Status (Esquerda)
        self._create_status_panel(main_frame, row=1, column=0)
        
        # Painel de topologia/grafo (Centro)
        self._create_topology_panel(main_frame, row=1, column=1, rowspan=2)
        
        # Painel de mensagens/mensagens (Direita)
        self._create_messages_panel(main_frame, row=1, column=2, rowspan=2)
        
        # Painel de Controlo (Baixo esquerda)
        self._create_control_panel(main_frame, row=2, column=0)

    def _create_status_panel(self, parent, row, column):
        """Cria painel de estado da conexão"""
        frame = ttk.LabelFrame(parent, text="Estado da Conexão", padding="10")
        frame.grid(row=row, column=column, padx=5, pady=5, sticky=(tk.N, tk.S, tk.W))
        frame.columnconfigure(0, weight=1)

        # Informações do nó
        self.lbl_nid = ttk.Label(frame, text="NID: --", wraplength=200)
        self.lbl_nid.grid(row=0, column=0, sticky=tk.W, pady=2)
        
        self.lbl_state = ttk.Label(frame, text="Estado: DISCONNECTED", 
                                  style="Disconnected.TLabel")
        self.lbl_state.grid(row=1, column=0, sticky=tk.W, pady=2)
        
        self.lbl_uplink = ttk.Label(frame, text="Uplink: --")
        self.lbl_uplink.grid(row=2, column=0, sticky=tk.W, pady=2)
        
        self.lbl_hops = ttk.Label(frame, text="Hops: --")
        self.lbl_hops.grid(row=3, column=0, sticky=tk.W, pady=2)
        
        self.lbl_downlinks = ttk.Label(frame, text="Downlinks: 0")
        self.lbl_downlinks.grid(row=4, column=0, sticky=tk.W, pady=2)
        
        # Estatísticas
        ttk.Separator(frame, orient=tk.HORIZONTAL).grid(
            row=5, column=0, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Label(frame, text="Estatísticas", style="Header.TLabel").grid(
            row=6, column=0, sticky=tk.W, pady=(0, 5))
        
        self.lbl_stats = ttk.Label(frame, text="Msgs routeadas: 0\nHeartbeats perdidos: 0")
        self.lbl_stats.grid(row=7, column=0, sticky=tk.W)

    def _create_topology_panel(self, parent, row, column, rowspan=1):
        """Cria visualização da topologia (canvas)"""
        frame = ttk.LabelFrame(parent, text="Topologia da Rede", padding="5")
        frame.grid(row=row, column=column, rowspan=rowspan, padx=5, pady=5, 
                  sticky=(tk.N, tk.S, tk.E, tk.W))
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        # Canvas para desenho do grafo
        self.canvas = tk.Canvas(frame, bg='white', width=400, height=500)
        self.canvas.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        
        # Scrollbars
        h_scroll = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.canvas.xview)
        h_scroll.grid(row=1, column=0, sticky=(tk.W, tk.E))
        v_scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.canvas.yview)
        v_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.canvas.configure(xscrollcommand=h_scroll.set, yscrollcommand=v_scroll.set)
        
        # Legenda
        legend_frame = ttk.Frame(frame)
        legend_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)
        tk.Label(legend_frame, text="● Sink", fg="red").pack(side=tk.LEFT, padx=5)
        tk.Label(legend_frame, text="● Este nó", fg="blue").pack(side=tk.LEFT, padx=5)
        tk.Label(legend_frame, text="● Conectado", fg="green").pack(side=tk.LEFT, padx=5)
        tk.Label(legend_frame, text="● Recuperando", fg="orange").pack(side=tk.LEFT, padx=5)

    def _create_messages_panel(self, parent, row, column, rowspan=1):
        """Cria painel de mensagens"""
        frame = ttk.LabelFrame(parent, text="Mensagens & Logs", padding="5")
        frame.grid(row=row, column=column, rowspan=rowspan, padx=5, pady=5,
                  sticky=(tk.N, tk.S, tk.E))
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        # Notebook para separar mensagens recebidas e logs
        self.notebook = ttk.Notebook(frame)
        self.notebook.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        
        # Tab 1: Mensagens recebidas
        msg_frame = ttk.Frame(self.notebook)
        self.notebook.add(msg_frame, text="Mensagens")
        
        self.txt_messages = scrolledtext.ScrolledText(
            msg_frame, wrap=tk.WORD, width=40, height=20)
        self.txt_messages.pack(fill=tk.BOTH, expand=True)
        
        # Tab 2: Logs do sistema
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="Logs")
        
        self.txt_logs = scrolledtext.ScrolledText(
            log_frame, wrap=tk.WORD, width=40, height=20)
        self.txt_logs.pack(fill=tk.BOTH, expand=True)
        
        # Entry para enviar mensagens
        input_frame = ttk.Frame(frame)
        input_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.msg_target = ttk.Combobox(input_frame, width=15, state='readonly')
        self.msg_target['values'] = ('Sink', 'Broadcast')
        self.msg_target.set('Sink')
        self.msg_target.pack(side=tk.LEFT, padx=2)
        
        self.msg_entry = ttk.Entry(input_frame)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        
        send_btn = ttk.Button(input_frame, text="Enviar", command=self._on_send_click)
        send_btn.pack(side=tk.LEFT, padx=2)

    def _create_control_panel(self, parent, row, column):
        """Cria painel de controlo"""
        frame = ttk.LabelFrame(parent, text="Controlo", padding="10")
        frame.grid(row=row, column=column, padx=5, pady=5, sticky=(tk.S, tk.W, tk.E))

        # Botões de ação
        if not self.is_sink:
            btn_join = ttk.Button(frame, text="Join Network", 
                                 command=self._on_join_click)
            btn_join.grid(row=0, column=0, padx=2, pady=2)
            
            btn_leave = ttk.Button(frame, text="Leave", 
                                  command=self._on_leave_click)
            btn_leave.grid(row=0, column=1, padx=2, pady=2)
            
            btn_recover = ttk.Button(frame, text="Force Recover", 
                                    command=self._on_recover_click)
            btn_recover.grid(row=0, column=2, padx=2, pady=2)

        btn_scan = ttk.Button(frame, text="Scan BLE", 
                             command=self._on_scan_click)
        btn_scan.grid(row=1, column=0, padx=2, pady=2)
        
        btn_topo = ttk.Button(frame, text="Update Topology", 
                             command=self._on_topology_click)
        btn_topo.grid(row=1, column=1, padx=2, pady=2)
        
        btn_clear = ttk.Button(frame, text="Clear Logs", 
                              command=self._clear_logs)
        btn_clear.grid(row=1, column=2, padx=2, pady=2)

        # Atualização automática
        ttk.Checkbutton(frame, text="Auto-refresh", 
                       command=self._toggle_auto_refresh).grid(
                       row=2, column=0, columnspan=3, sticky=tk.W, pady=5)
        self.auto_refresh = False

    def _process_updates(self):
        """Processa updates da queue (thread-safe)"""
        while self.update_queue:
            try:
                func = self.update_queue.popleft()
                func()
            except Exception as e:
                print(f"Erro no update GUI: {e}")
        
        self.root.after(100, self._process_updates)

    def queue_update(self, func):
        """Adiciona função à queue para execução na thread da GUI"""
        self.update_queue.append(func)

    def update_status(self, nid: str, state: str, uplink: Optional[str], 
                     hops: int, downlinks: int, stats: Dict):
        """Atualiza painel de status"""
        def _update():
            self.lbl_nid.config(text=f"NID: {nid[:20]}...")
            self.lbl_state.config(text=f"Estado: {state}")
            
            # Cor baseada no estado
            if state == "CONNECTED" or state == "NETWORK_JOINED":
                self.lbl_state.config(style="Connected.TLabel")
            elif state == "RECOVERING":
                self.lbl_state.config(style="Recovering.TLabel")
            else:
                self.lbl_state.config(style="Disconnected.TLabel")
            
            self.lbl_uplink.config(text=f"Uplink: {uplink[:20] if uplink else '--'}...")
            self.lbl_hops.config(text=f"Hops: {hops}")
            self.lbl_downlinks.config(text=f"Downlinks: {downlinks}")
            
            stats_text = f"Msgs: {stats.get('routed', 0)}\n"
            stats_text += f"Lost HB: {stats.get('lost_hb', 0)}\n"
            stats_text += f"Queue: {stats.get('queue', 0)}"
            self.lbl_stats.config(text=stats_text)
            
        self.queue_update(_update)

    def update_topology(self, nodes: List[Dict], edges: List[Tuple]):
        """Atualiza visualização da topologia"""
        def _draw():
            self.canvas.delete("all")
            
            # Posicionamento hierárquico simples
            positions = {}
            levels = {}
            
            # Calcula níveis (simplificado)
            for node in nodes:
                nid = node.get('nid', '')
                hop = node.get('hops', 0)
                if nid not in levels or hop < levels[nid]:
                    levels[nid] = hop
            
            # Agrupa por nível
            level_nodes = {}
            for nid, level in levels.items():
                if level not in level_nodes:
                    level_nodes[level] = []
                level_nodes[level].append(nid)
            
            # Desenha nós
            y_spacing = 80
            x_spacing = 100
            node_radius = 20
            
            for level, nids in sorted(level_nodes.items()):
                y = 50 + level * y_spacing
                count = len(nids)
                total_width = (count - 1) * x_spacing
                start_x = 200 - total_width // 2
                
                for i, nid in enumerate(nids):
                    x = start_x + i * x_spacing
                    positions[nid] = (x, y)
                    
                    # Determina cor
                    color = "green"  # default
                    if node.get('is_sink'):
                        color = "red"
                    elif node.get('is_self'):
                        color = "blue"
                    elif node.get('state') == 'RECOVERING':
                        color = "orange"
                    
                    # Desenha círculo
                    self.canvas.create_oval(
                        x-node_radius, y-node_radius,
                        x+node_radius, y+node_radius,
                        fill=color, outline="black", width=2
                    )
                    
                    # Label
                    label = nid[:8] + "..."
                    self.canvas.create_text(x, y+node_radius+15, text=label, font=("Courier", 8))
                    
                    # Hops info
                    if 'hops' in node:
                        self.canvas.create_text(x, y, text=str(node['hops']), 
                                               fill="white", font=("Arial", 10, "bold"))
            
            # Desenha arestas
            for edge in edges:
                if edge[0] in positions and edge[1] in positions:
                    x1, y1 = positions[edge[0]]
                    x2, y2 = positions[edge[1]]
                    self.canvas.create_line(x1, y1, x2, y2, arrow=tk.LAST, width=2)
            
            # Ajusta scroll region
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))
            
        self.queue_update(_draw)

    def add_message(self, source: str, content: str, timestamp: str = None):
        """Adiciona mensagem ao painel"""
        def _add():
            ts = timestamp or datetime.now().strftime("%H:%M:%S")
            self.txt_messages.insert(tk.END, f"[{ts}] {source}:\n{content}\n\n")
            self.txt_messages.see(tk.END)
        self.queue_update(_add)

    def log(self, message: str, level: str = "INFO"):
        """Adiciona log ao sistema"""
        def _log():
            ts = datetime.now().strftime("%H:%M:%S")
            color = {"INFO": "black", "WARNING": "orange", 
                    "ERROR": "red", "SUCCESS": "green"}.get(level, "black")
            
            self.txt_logs.insert(tk.END, f"[{ts}] [{level}] {message}\n")
            self.txt_logs.tag_config(level, foreground=color)
            self.txt_logs.tag_add(level, f"end-2l linestart", "end-1l")
            self.txt_logs.see(tk.END)
        self.queue_update(_log)

    def update_known_nodes(self, nodes: List[str]):
        """Atualiza lista de nós conhecidos no dropdown"""
        def _update():
            if not self.is_sink:
                values = ['Sink'] + [n[:16] + "..." for n in nodes]
                self.msg_target['values'] = values
        self.queue_update(_update)

    # Callbacks de botões
    def _on_send_click(self):
        target = self.msg_target.get()
        msg = self.msg_entry.get()
        if msg and self.on_send_message:
            self.on_send_message(target, msg)
            self.msg_entry.delete(0, tk.END)

    def _on_join_click(self):
        if self.on_command:
            self.on_command("join")

    def _on_leave_click(self):
        if self.on_command:
            self.on_command("leave")

    def _on_recover_click(self):
        if self.on_command:
            self.on_command("force_recover")

    def _on_scan_click(self):
        if self.on_scan_network:
            self.on_scan_network()

    def _on_topology_click(self):
        if self.on_command:
            self.on_command("update_topology")

    def _clear_logs(self):
        self.txt_logs.delete(1.0, tk.END)

    def _toggle_auto_refresh(self):
        self.auto_refresh = not self.auto_refresh
        if self.auto_refresh and self.on_command:
            self._auto_refresh_loop()

    def _auto_refresh_loop(self):
        if self.auto_refresh:
            self.on_command("refresh_status")
            self.root.after(2000, self._auto_refresh_loop)

    def show_error(self, title: str, message: str):
        """Mostra diálogo de erro"""
        def _show():
            messagebox.showerror(title, message)
        self.queue_update(_show)

    def run(self):
        """Inicia loop da GUI"""
        self.root.mainloop()

    def close(self):
        """Fecha GUI"""
        if self.root:
            self.root.quit()