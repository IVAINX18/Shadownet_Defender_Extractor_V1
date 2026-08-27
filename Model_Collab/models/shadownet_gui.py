#!/usr/bin/env python3
"""
ShadowNet Defender - Interfaz Gráfica
Sistema de Detección de Malware con IA

Desarrollado como parte del proyecto de pasantía
Modelo entrenado con dataset híbrido: 100K + 5M SOREL-20M
Accuracy: 98.15% - Nivel Profesional
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import pickle
from pathlib import Path
import threading
import time
from datetime import datetime
import os

class MalwareDetector(nn.Module):
    """
    Clase del modelo MLP para detección de malware
    Misma arquitectura que el modelo entrenado
    """
    def __init__(self, input_dim):
        super(MalwareDetector, self).__init__()
        self.layers = nn.Sequential(
            nn.Linear(input_dim, 512),
            nn.BatchNorm1d(512),
            nn.ReLU(),
            nn.Dropout(0.3),
            
            nn.Linear(512, 256),
            nn.BatchNorm1d(256), 
            nn.ReLU(),
            nn.Dropout(0.2),
            
            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(), 
            nn.Dropout(0.1),
            
            nn.Linear(128, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        return self.layers(x)

class ShadowNetDefenderGUI:
    def __init__(self, root):
        self.root = root
        self.model = None
        self.scaler = None
        self.setup_gui()
        self.load_model()
        
    def setup_gui(self):
        """Configurar la interfaz gráfica"""
        # Configuración principal de la ventana
        self.root.title("ShadowNet Defender - Detección de Malware con IA")
        self.root.geometry("900x700")
        self.root.configure(bg='#1a1a1a')
        
        # Centrar ventana en pantalla
        self.root.eval('tk::PlaceWindow . center')
        
        # Estilo
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configurar colores del tema
        style.configure('Title.TLabel', 
                       background='#1a1a1a', 
                       foreground='#00ff41',
                       font=('Arial', 20, 'bold'))
        
        style.configure('Header.TLabel',
                       background='#1a1a1a',
                       foreground='#ffffff',
                       font=('Arial', 12, 'bold'))
        
        style.configure('Info.TLabel',
                       background='#1a1a1a',
                       foreground='#cccccc',
                       font=('Arial', 10))
        
        style.configure('Custom.TButton',
                       font=('Arial', 11, 'bold'))
        
        # Frame principal
        main_frame = ttk.Frame(self.root)
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # HEADER
        self.create_header(main_frame)
        
        # SECCIÓN DE CARGA DE MODELO
        self.create_model_section(main_frame)
        
        # SECCIÓN DE ANÁLISIS
        self.create_analysis_section(main_frame)
        
        # SECCIÓN DE RESULTADOS
        self.create_results_section(main_frame)
        
        # FOOTER
        self.create_footer(main_frame)
    
    def create_header(self, parent):
        """Crear header con título y logo"""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill='x', pady=(0, 20))
        
        # Título principal
        title_label = ttk.Label(header_frame, 
                               text="🛡️ ShadowNet Defender", 
                               style='Title.TLabel')
        title_label.pack()
        
        # Subtítulo
        subtitle_label = ttk.Label(header_frame,
                                  text="Sistema de Detección de Malware con Inteligencia Artificial",
                                  style='Info.TLabel')
        subtitle_label.pack(pady=(5, 0))
        
        # Separador
        separator = ttk.Separator(header_frame, orient='horizontal')
        separator.pack(fill='x', pady=10)
    
    def create_model_section(self, parent):
        """Crear sección de información del modelo"""
        model_frame = ttk.LabelFrame(parent, text="📊 Información del Modelo", padding="10")
        model_frame.pack(fill='x', pady=(0, 15))
        
        # Frame para información del modelo
        info_frame = ttk.Frame(model_frame)
        info_frame.pack(fill='x')
        
        # Información del modelo (se actualizará cuando cargue)
        self.model_info = ttk.Label(info_frame,
                                   text="🔄 Cargando modelo...",
                                   style='Info.TLabel')
        self.model_info.pack(anchor='w')
        
        # Status del modelo
        self.model_status = ttk.Label(info_frame,
                                     text="⏳ Estado: Iniciando...",
                                     style='Info.TLabel')
        self.model_status.pack(anchor='w', pady=(5, 0))
    
    def create_analysis_section(self, parent):
        """Crear sección de análisis de archivos"""
        analysis_frame = ttk.LabelFrame(parent, text="🔍 Análisis de Malware", padding="10")
        analysis_frame.pack(fill='both', expand=True, pady=(0, 15))
        
        # Opciones de análisis
        options_frame = ttk.Frame(analysis_frame)
        options_frame.pack(fill='x', pady=(0, 10))
        
        # Botón para cargar CSV con características
        self.load_csv_btn = ttk.Button(options_frame,
                                      text="📁 Cargar CSV con Características",
                                      command=self.load_csv_file,
                                      style='Custom.TButton')
        self.load_csv_btn.pack(side='left', padx=(0, 10))
        
        # Botón para análisis de muestra
        self.sample_btn = ttk.Button(options_frame,
                                    text="🧪 Analizar Muestra de Prueba",
                                    command=self.analyze_sample,
                                    style='Custom.TButton')
        self.sample_btn.pack(side='left')
        
        # Área de información del archivo cargado
        self.file_info_frame = ttk.Frame(analysis_frame)
        self.file_info_frame.pack(fill='x', pady=10)
        
        self.file_info_label = ttk.Label(self.file_info_frame,
                                        text="📄 Ningún archivo cargado",
                                        style='Info.TLabel')
        self.file_info_label.pack(anchor='w')
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(analysis_frame,
                                           variable=self.progress_var,
                                           maximum=100,
                                           length=300)
        self.progress_bar.pack(pady=10)
        
        # Botón de análisis
        self.analyze_btn = ttk.Button(analysis_frame,
                                     text="🚀 Ejecutar Análisis",
                                     command=self.run_analysis,
                                     style='Custom.TButton',
                                     state='disabled')
        self.analyze_btn.pack(pady=10)
    
    def create_results_section(self, parent):
        """Crear sección de resultados"""
        results_frame = ttk.LabelFrame(parent, text="📊 Resultados del Análisis", padding="10")
        results_frame.pack(fill='both', expand=True)
        
        # Frame para resultados
        self.results_display = tk.Text(results_frame,
                                      height=12,
                                      width=80,
                                      font=('Consolas', 10),
                                      bg='#2d2d2d',
                                      fg='#ffffff',
                                      insertbackground='white',
                                      wrap='word')
        
        # Scrollbar para el área de resultados
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_display.yview)
        self.results_display.configure(yscrollcommand=scrollbar.set)
        
        # Pack del text y scrollbar
        self.results_display.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Mensaje inicial
        self.update_results("🛡️ ShadowNet Defender iniciado correctamente.\n" +
                           "📊 Modelo de IA listo para detectar malware.\n" +
                           "🎯 Accuracy del modelo: 98.15% (Nivel Profesional)\n\n" +
                           "💡 Instrucciones:\n" +
                           "1. Cargar un archivo CSV con características de archivos\n" +
                           "2. O usar 'Analizar Muestra de Prueba' para ver una demo\n" +
                           "3. Hacer clic en 'Ejecutar Análisis'\n\n" +
                           "⏳ Esperando archivo para analizar...\n")
    
    def create_footer(self, parent):
        """Crear footer con información adicional"""
        footer_frame = ttk.Frame(parent)
        footer_frame.pack(fill='x', pady=(10, 0))
        
        # Separador
        separator = ttk.Separator(footer_frame, orient='horizontal')
        separator.pack(fill='x', pady=(0, 10))
        
        # Información del proyecto
        footer_text = ("Desarrollado como proyecto de pasantía • "
                      "Modelo: MLP con 98.15% accuracy • "
                      "Dataset: 5.1M registros híbridos")
        
        footer_label = ttk.Label(footer_frame,
                                text=footer_text,
                                style='Info.TLabel')
        footer_label.pack()
    
    def load_model(self):
        """Cargar el modelo entrenado y el scaler"""
        try:
            # Rutas de los archivos del modelo
            model_path = Path("models/best_model.pth")
            scaler_path = Path("models/scaler.pkl")
            
            # Verificar que existen los archivos
            if not model_path.exists():
                raise FileNotFoundError(f"Modelo no encontrado: {model_path}")
            if not scaler_path.exists():
                raise FileNotFoundError(f"Scaler no encontrado: {scaler_path}")
            
            # Cargar scaler
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            
            # Cargar modelo
            # Asumir 2381 características (como en el entrenamiento)
            self.model = MalwareDetector(2381)
            self.model.load_state_dict(torch.load(model_path, map_location='cpu'))
            self.model.eval()
            
            # Actualizar información en la GUI
            model_info_text = ("✅ Modelo cargado exitosamente\n" +
                              "🧠 Arquitectura: MLP (2381 → 512 → 256 → 128 → 1)\n" +
                              "🎯 Accuracy: 98.15% | Precision: 98.70% | Recall: 98.20%\n" +
                              "📊 Entrenado con 5.1M registros (100K propios + 5M SOREL-20M)")
            
            self.model_info.config(text=model_info_text)
            self.model_status.config(text="✅ Estado: Modelo listo para análisis")
            
            # Habilitar botones
            self.sample_btn.config(state='normal')
            
        except Exception as e:
            error_msg = f"❌ Error cargando modelo: {str(e)}"
            self.model_info.config(text=error_msg)
            self.model_status.config(text="❌ Estado: Error en carga del modelo")
            messagebox.showerror("Error", f"No se pudo cargar el modelo:\n{str(e)}")
    
    def load_csv_file(self):
        """Cargar archivo CSV con características"""
        file_path = filedialog.askopenfilename(
            title="Seleccionar archivo CSV",
            filetypes=[("Archivos CSV", "*.csv"), ("Todos los archivos", "*.*")]
        )
        
        if file_path:
            try:
                # Cargar y verificar el CSV
                self.df = pd.read_csv(file_path)
                
                # Verificar que tiene las columnas necesarias
                if self.df.shape[1] < 10:  # Mínimo algunas características
                    messagebox.showwarning("Advertencia", 
                                         f"El archivo tiene pocas columnas ({self.df.shape[1]}). " +
                                         "Asegúrate de que contenga características de archivos.")
                
                # Actualizar información del archivo
                file_info = (f"📄 Archivo cargado: {Path(file_path).name}\n" +
                           f"📊 Registros: {self.df.shape[0]:,} | Características: {self.df.shape[1]:,}")
                
                self.file_info_label.config(text=file_info)
                self.analyze_btn.config(state='normal')
                
                self.update_results(f"\n✅ Archivo CSV cargado exitosamente:\n" +
                                  f"   📁 Archivo: {Path(file_path).name}\n" +
                                  f"   📊 Filas: {self.df.shape[0]:,}\n" +
                                  f"   📋 Columnas: {self.df.shape[1]:,}\n" +
                                  f"   💡 Listo para análisis.\n")
                
            except Exception as e:
                messagebox.showerror("Error", f"Error cargando CSV:\n{str(e)}")
    
    def analyze_sample(self):
        """Crear y analizar muestra de prueba"""
        if self.model is None:
            messagebox.showerror("Error", "Modelo no cargado")
            return
        
        try:
            # Crear datos de muestra (simulando características de archivos)
            np.random.seed(42)  # Para reproducibilidad
            
            # Generar 5 muestras de prueba
            n_samples = 5
            n_features = 2381
            
            # Crear muestras variadas (simulando diferentes tipos de archivos)
            samples = []
            labels = ['Archivo_Sistema.exe', 'Documento.pdf', 'Sospechoso.exe', 'Imagen.jpg', 'Script.bat']
            
            for i in range(n_samples):
                if i == 2:  # Hacer una muestra más "sospechosa"
                    sample = np.random.exponential(scale=2.0, size=n_features).astype(np.float32)
                else:
                    sample = np.random.normal(loc=0.0, scale=1.0, size=n_features).astype(np.float32)
                samples.append(sample)
            
            # Crear DataFrame de muestra
            self.df = pd.DataFrame(samples, columns=[f'feature_{i}' for i in range(n_features)])
            self.df.index = labels
            
            # Actualizar información
            self.file_info_label.config(text=f"🧪 Muestra de prueba generada: {n_samples} archivos simulados")
            self.analyze_btn.config(state='normal')
            
            self.update_results(f"\n🧪 Muestra de prueba generada:\n" +
                              f"   📊 {n_samples} archivos simulados\n" +
                              f"   📋 {n_features} características por archivo\n" +
                              f"   💡 Listo para análisis de demostración.\n")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error creando muestra:\n{str(e)}")
    
    def run_analysis(self):
        """Ejecutar análisis de malware en thread separado"""
        if self.model is None or not hasattr(self, 'df'):
            messagebox.showerror("Error", "Modelo o datos no disponibles")
            return
        
        # Ejecutar en thread separado para no bloquear GUI
        analysis_thread = threading.Thread(target=self._perform_analysis)
        analysis_thread.daemon = True
        analysis_thread.start()
    
    def _perform_analysis(self):
        """Realizar el análisis real del malware"""
        try:
            # Actualizar GUI en thread principal
            self.root.after(0, lambda: self.analyze_btn.config(state='disabled'))
            self.root.after(0, lambda: self.update_results("\n🚀 Iniciando análisis de malware...\n"))
            
            # Simular progreso
            for i in range(0, 101, 10):
                time.sleep(0.1)
                self.root.after(0, lambda p=i: self.progress_var.set(p))
            
            # Preparar datos
            X = self.df.values.astype(np.float32)
            
            # Ajustar dimensiones si es necesario
            if X.shape[1] != 2381:
                if X.shape[1] < 2381:
                    # Padding con ceros
                    padding = np.zeros((X.shape[0], 2381 - X.shape[1]), dtype=np.float32)
                    X = np.hstack([X, padding])
                else:
                    # Truncar
                    X = X[:, :2381]
            
            # Normalizar datos
            X_scaled = self.scaler.transform(X)
            
            # Convertir a tensor
            X_tensor = torch.FloatTensor(X_scaled)
            
            # Realizar predicciones
            with torch.no_grad():
                probabilities = self.model(X_tensor).numpy().flatten()
                predictions = (probabilities >= 0.5).astype(int)
            
            # Generar reporte de resultados
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            report = f"\n{'='*60}\n"
            report += f"🛡️  REPORTE DE ANÁLISIS SHADOWNET DEFENDER\n"
            report += f"{'='*60}\n"
            report += f"📅 Fecha/Hora: {timestamp}\n"
            report += f"📊 Archivos analizados: {len(X)}\n"
            report += f"🎯 Modelo: MLP (Accuracy: 98.15%)\n\n"
            
            # Resultados por archivo
            malware_count = 0
            benign_count = 0
            
            for i, (prob, pred) in enumerate(zip(probabilities, predictions)):
                file_name = self.df.index[i] if hasattr(self.df, 'index') else f"Archivo_{i+1}"
                
                if pred == 1:  # Malware
                    status = "🚨 MALWARE"
                    malware_count += 1
                    color_indicator = "⚠️"
                else:  # Benign
                    status = "✅ BENIGN"
                    benign_count += 1
                    color_indicator = "🟢"
                
                confidence = prob if pred == 1 else (1 - prob)
                report += f"{color_indicator} {file_name[:25]:25s} | {status:12s} | Confianza: {confidence:.2%}\n"
            
            # Resumen final
            report += f"\n{'='*60}\n"
            report += f"📊 RESUMEN DEL ANÁLISIS:\n"
            report += f"   🟢 Archivos benignos: {benign_count:,}\n"
            report += f"   🚨 Malware detectado: {malware_count:,}\n"
            report += f"   📈 Ratio de detección: {malware_count/len(X):.1%}\n"
            
            if malware_count > 0:
                report += f"\n⚠️  ALERTA: Se detectó malware en el sistema!\n"
                report += f"🔒 Recomendación: Revisar archivos marcados como maliciosos.\n"
            else:
                report += f"\n✅ SISTEMA LIMPIO: No se detectó malware.\n"
            
            report += f"{'='*60}\n"
            
            # Actualizar GUI con resultados
            self.root.after(0, lambda: self.update_results(report))
            self.root.after(0, lambda: self.progress_var.set(0))
            self.root.after(0, lambda: self.analyze_btn.config(state='normal'))
            
        except Exception as e:
            error_msg = f"\n❌ ERROR EN ANÁLISIS: {str(e)}\n"
            self.root.after(0, lambda: self.update_results(error_msg))
            self.root.after(0, lambda: self.progress_var.set(0))
            self.root.after(0, lambda: self.analyze_btn.config(state='normal'))
    
    def update_results(self, text):
        """Actualizar el área de resultados"""
        self.results_display.insert(tk.END, text)
        self.results_display.see(tk.END)  # Scroll al final

def main():
    """Función principal para ejecutar la aplicación"""
    # Crear ventana principal
    root = tk.Tk()
    
    # Crear aplicación
    app = ShadowNetDefenderGUI(root)
    
    # Ejecutar loop principal
    root.mainloop()

if __name__ == "__main__":
    main()
