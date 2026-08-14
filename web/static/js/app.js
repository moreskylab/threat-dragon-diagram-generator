// Dragon-GPT Cloud Studio Application Logic

document.addEventListener('DOMContentLoaded', () => {
  // State
  let currentTemplateId = 'ecommerce';
  let currentJsonData = null;
  let currentSvgData = null;
  let currentReportMarkdown = null;
  let currentPromptText = null;

  // AI Configuration State (stored in localStorage)
  let aiConfig = {
    apiKey: localStorage.getItem('dragon_gpt_api_key') || '',
    model: localStorage.getItem('dragon_gpt_model') || '',
    baseUrl: localStorage.getItem('dragon_gpt_base_url') || '',
    temperature: parseFloat(localStorage.getItem('dragon_gpt_temp') || '0.2'),
  };

  // DOM Elements
  const healthStatusText = document.getElementById('healthStatusText');
  const templateList = document.getElementById('templateList');
  const dropZone = document.getElementById('dropZone');
  const fileUploadInput = document.getElementById('fileUploadInput');
  const methodologySelect = document.getElementById('methodologySelect');
  const btnInspectPrompt = document.getElementById('btnInspectPrompt');
  const btnRunThreatModel = document.getElementById('btnRunThreatModel');

  const diagramViewer = document.getElementById('diagramViewer');
  const reportViewer = document.getElementById('reportViewer');
  const reportHeaderBar = document.getElementById('reportHeaderBar');
  const reportModelBadge = document.getElementById('reportModelBadge');
  const reportTimeBadge = document.getElementById('reportTimeBadge');
  const promptCodeBlock = document.getElementById('promptCodeBlock');
  const promptMetaBar = document.getElementById('promptMetaBar');
  const promptElementsBadge = document.getElementById('promptElementsBadge');
  const promptFlowsBadge = document.getElementById('promptFlowsBadge');
  const jsonEditor = document.getElementById('jsonEditor');

  const btnDownloadJson = document.getElementById('btnDownloadJson');
  const btnDownloadSvg = document.getElementById('btnDownloadSvg');
  const btnDownloadReport = document.getElementById('btnDownloadReport');
  const btnCopyPrompt = document.getElementById('btnCopyPrompt');
  const btnCopyJson = document.getElementById('btnCopyJson');

  const btnOpenSettings = document.getElementById('btnOpenSettings');
  const btnCloseSettings = document.getElementById('btnCloseSettings');
  const btnSaveSettings = document.getElementById('btnSaveSettings');
  const settingsModal = document.getElementById('settingsModal');
  const cfgApiKey = document.getElementById('cfgApiKey');
  const cfgModel = document.getElementById('cfgModel');
  const cfgBaseUrl = document.getElementById('cfgBaseUrl');
  const cfgTemperature = document.getElementById('cfgTemperature');
  const tempValueDisplay = document.getElementById('tempValueDisplay');

  const loadingOverlay = document.getElementById('loadingOverlay');
  const loadingTitle = document.getElementById('loadingTitle');
  const loadingSubtitle = document.getElementById('loadingSubtitle');

  // Tab Switching
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  function switchTab(tabId) {
    tabButtons.forEach(btn => {
      btn.classList.toggle('active', btn.dataset.tab === tabId);
    });
    tabContents.forEach(content => {
      content.classList.toggle('active', content.id === tabId);
    });
  }

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  // UI Helpers
  function showLoading(title = 'Processing...', subtitle = 'Consulting threat engine...') {
    loadingTitle.textContent = title;
    loadingSubtitle.textContent = subtitle;
    loadingOverlay.style.display = 'flex';
  }

  function hideLoading() {
    loadingOverlay.style.display = 'none';
  }

  // 1. Health Probe Polling
  async function checkHealth() {
    try {
      const res = await fetch('/healthz');
      if (res.ok) {
        const data = await res.json();
        healthStatusText.textContent = `Healthy (v${data.version} | Up: ${data.uptime_seconds}s)`;
        healthStatusText.style.color = '#34d399';
      } else {
        healthStatusText.textContent = 'Degraded';
        healthStatusText.style.color = '#f87171';
      }
    } catch (e) {
      healthStatusText.textContent = 'Offline';
      healthStatusText.style.color = '#f87171';
    }
  }
  checkHealth();
  setInterval(checkHealth, 15000);

  // 2. Fetch Templates
  async function loadTemplates() {
    try {
      const res = await fetch('/api/v1/templates');
      if (!res.ok) throw new Error('Failed to load templates');
      const templates = await res.json();

      templateList.innerHTML = '';
      templates.forEach((tpl, idx) => {
        const card = document.createElement('div');
        card.className = `template-card ${tpl.id === currentTemplateId ? 'active' : ''}`;
        card.dataset.id = tpl.id;
        card.innerHTML = `
          <div class="template-name">${tpl.name}</div>
          <div class="template-summary">${tpl.description}</div>
        `;
        card.addEventListener('click', () => selectTemplate(tpl.id));
        templateList.appendChild(card);
      });

      // Load initial template
      if (templates.length > 0) {
        selectTemplate(templates[0].id);
      }
    } catch (err) {
      templateList.innerHTML = `<div style="color: #f87171; font-size: 0.8rem;">Failed to load templates: ${err.message}</div>`;
    }
  }

  // 3. Select & Render Template
  async function selectTemplate(templateId) {
    currentTemplateId = templateId;
    document.querySelectorAll('.template-card').forEach(c => {
      c.classList.toggle('active', c.dataset.id === templateId);
    });

    const methodology = methodologySelect.value;
    showLoading('Loading Architecture...', `Generating ${templateId} model`);

    try {
      const res = await fetch(`/api/v1/templates/${templateId}?diagram_type=${methodology}`);
      if (!res.ok) throw new Error('Failed to fetch template model');
      const data = await res.json();

      currentJsonData = data.json_data;
      currentSvgData = data.svg_content;

      // Update UI
      diagramViewer.innerHTML = data.svg_content;
      jsonEditor.value = JSON.stringify(data.json_data, null, 2);

      switchTab('tabDiagram');
    } catch (err) {
      alert(`Error loading template: ${err.message}`);
    } finally {
      hideLoading();
    }
  }

  methodologySelect.addEventListener('change', () => {
    if (currentTemplateId) {
      selectTemplate(currentTemplateId);
    }
  });

  // 4. File Upload / Drag & Drop
  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
  });

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  });

  fileUploadInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handleFileUpload(e.target.files[0]);
    }
  });

  async function handleFileUpload(file) {
    if (!file.name.endsWith('.json')) {
      alert('Please upload an OWASP Threat Dragon .json file.');
      return;
    }

    showLoading('Reading File...', `Parsing ${file.name}`);
    try {
      const text = await file.text();
      const json = JSON.parse(text);
      currentJsonData = json;
      currentTemplateId = null;

      // De-select all template cards
      document.querySelectorAll('.template-card').forEach(c => c.classList.remove('active'));

      jsonEditor.value = JSON.stringify(json, null, 2);

      // Render uploaded JSON
      const renderRes = await fetch('/api/v1/render', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ diagram_data: json, format: 'svg' }),
      });

      if (renderRes.ok) {
        const renderData = await renderRes.json();
        currentSvgData = renderData.image_data;
        diagramViewer.innerHTML = renderData.image_data;
      } else {
        diagramViewer.innerHTML = '<div class="empty-state"><p>Uploaded JSON parsed. (Diagram preview unavailable)</p></div>';
      }

      switchTab('tabDiagram');
    } catch (err) {
      alert(`Invalid Threat Dragon JSON: ${err.message}`);
    } finally {
      hideLoading();
    }
  }

  // 5. Inspect Prompt (Dry Run)
  btnInspectPrompt.addEventListener('click', async () => {
    showLoading('Analyzing Architecture...', 'Generating LLM threat prompt');
    try {
      const payload = currentJsonData
        ? { diagram_data: currentJsonData }
        : { template_id: currentTemplateId };

      const res = await fetch('/api/v1/prompt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Failed to inspect prompt');
      }

      const data = await res.json();
      currentPromptText = data.prompt;

      promptCodeBlock.textContent = data.prompt;
      promptElementsBadge.textContent = `${data.element_count} Components`;
      promptFlowsBadge.textContent = `${data.flow_count} Data Flows`;
      promptMetaBar.style.display = 'flex';

      switchTab('tabPrompt');
    } catch (err) {
      alert(`Prompt Generation Error: ${err.message}`);
    } finally {
      hideLoading();
    }
  });

  // 6. Generate AI Threat Model Report
  btnRunThreatModel.addEventListener('click', async () => {
    showLoading(
      'Generating AI Threat Report...',
      'Executing STRIDE threat modeling via LLM (this may take a few seconds)...'
    );

    try {
      const payload = {
        diagram_data: currentJsonData,
        template_id: currentJsonData ? null : currentTemplateId,
        model_name: aiConfig.model || undefined,
        api_key: aiConfig.apiKey || undefined,
        base_url: aiConfig.baseUrl || undefined,
        temperature: aiConfig.temperature,
        include_prompt: true,
      };

      const res = await fetch('/api/v1/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Threat modeling analysis failed.');
      }

      const data = await res.json();
      currentReportMarkdown = data.report_markdown;

      // Render Markdown
      if (window.marked) {
        reportViewer.innerHTML = marked.parse(data.report_markdown);
      } else {
        reportViewer.innerHTML = `<pre>${data.report_markdown}</pre>`;
      }

      reportModelBadge.textContent = `Model: ${data.model_used}`;
      reportTimeBadge.textContent = `Latency: ${data.execution_time_seconds}s`;
      reportHeaderBar.style.display = 'flex';

      switchTab('tabThreatModel');
    } catch (err) {
      alert(`AI Threat Modeling Failed:\n${err.message}\n\nTip: Configure your OpenAI API Key or Local Base URL under "AI Config".`);
    } finally {
      hideLoading();
    }
  });

  // 7. Download & Export Handlers
  btnDownloadJson.addEventListener('click', () => {
    const jsonStr = jsonEditor.value || JSON.stringify(currentJsonData, null, 2);
    downloadFile(jsonStr, 'threat-dragon-model.json', 'application/json');
  });

  btnDownloadSvg.addEventListener('click', () => {
    if (currentSvgData) {
      downloadFile(currentSvgData, 'architecture-diagram.svg', 'image/svg+xml');
    } else {
      alert('No SVG diagram loaded to export.');
    }
  });

  btnDownloadReport.addEventListener('click', () => {
    if (currentReportMarkdown) {
      downloadFile(currentReportMarkdown, 'threat-model-report.md', 'text/markdown');
    }
  });

  btnCopyPrompt.addEventListener('click', () => {
    if (currentPromptText) {
      navigator.clipboard.writeText(currentPromptText);
      alert('Threat Modeling Prompt copied to clipboard!');
    }
  });

  btnCopyJson.addEventListener('click', () => {
    navigator.clipboard.writeText(jsonEditor.value);
    alert('Threat Dragon JSON copied to clipboard!');
  });

  function downloadFile(content, filename, contentType) {
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // 8. AI Settings Modal
  btnOpenSettings.addEventListener('click', () => {
    cfgApiKey.value = aiConfig.apiKey;
    cfgModel.value = aiConfig.model;
    cfgBaseUrl.value = aiConfig.baseUrl;
    cfgTemperature.value = aiConfig.temperature;
    tempValueDisplay.textContent = aiConfig.temperature;
    settingsModal.style.display = 'flex';
  });

  btnCloseSettings.addEventListener('click', () => {
    settingsModal.style.display = 'none';
  });

  cfgTemperature.addEventListener('input', (e) => {
    tempValueDisplay.textContent = e.target.value;
  });

  btnSaveSettings.addEventListener('click', () => {
    aiConfig.apiKey = cfgApiKey.value.trim();
    aiConfig.model = cfgModel.value.trim();
    aiConfig.baseUrl = cfgBaseUrl.value.trim();
    aiConfig.temperature = parseFloat(cfgTemperature.value);

    localStorage.setItem('dragon_gpt_api_key', aiConfig.apiKey);
    localStorage.setItem('dragon_gpt_model', aiConfig.model);
    localStorage.setItem('dragon_gpt_base_url', aiConfig.baseUrl);
    localStorage.setItem('dragon_gpt_temp', aiConfig.temperature.toString());

    settingsModal.style.display = 'none';
  });

  // Initial Load
  loadTemplates();
});
