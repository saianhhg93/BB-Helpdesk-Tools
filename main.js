// main.js
const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
// THAY ĐỔI: Chuyển 'spawn' vào dòng 'require' đã có sẵn
const { exec, spawn } = require('child_process');
const fs  = require('fs');
const os  = require('os');


let win;
let settingsWin;
let networkWin;
let bloatwareWin;
let bitlockerWin;
let backupDir = 'D:\\BB_Backup'; // mặc định; sau có thể load từ file config nếu muốn
let activationWin;

// Hàm thực thi PowerShell an toàn (đã sửa lại để dùng spawn và encodedCommand)

function runPowerShellCommand(script) {
  // Prelude to suppress progress/verbose/info and make errors fail the script
  const prelude = "$ProgressPreference='SilentlyContinue';$VerbosePreference='SilentlyContinue';$InformationPreference='SilentlyContinue';$WarningPreference='SilentlyContinue';$ErrorActionPreference='Stop';";
  const fullScript = prelude + "\n" + script;
  const b64 = Buffer.from(fullScript, 'utf16le').toString('base64');
  const ps = spawn('powershell.exe', ['-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand', b64], { windowsHide: true });
  return new Promise((resolve) => {
    let out = '', err = '';
    ps.stdout.on('data', d => out += d.toString('utf8'));
    ps.stderr.on('data', d => err += d.toString('utf8'));
    ps.on('close', code => {
      if (code === 0) {
        resolve({ success: true, message: 'Success!', data: out.trim() });
      } else {
        resolve({ success: false, message: err || out, data: null });
      }
    });
  });
}
function runExeCommand(command) {
    return new Promise(resolve => {
        exec(command, (error, stdout, stderr) => {
            if (error || stderr) {
                console.error("Execution Error:", error || stderr);
                resolve({ success: false, message: error ? error.message : stderr });
            } else {
                resolve({ success: true, message: 'Thành công!' });
            }
        });
    });
}

// Trả về đường dẫn asset đúng ở dev/packaged
function runtimeAsset(p) {
  return app.isPackaged ? path.join(process.resourcesPath, p) : path.join(__dirname, p);
}
function runtimeIcon() {
  const p = runtimeAsset('icon.ico');
  return fs.existsSync(p) ? p : undefined;    // có thì dùng, không có thì để Electron tự fallback
}

// ========== MAIN WINDOW ==========
function createWindow() {
  win = new BrowserWindow({
    width: 900,
    height: 650,
    show: false,                   // chỉ show khi sẵn sàng
    icon: runtimeIcon(),
    frame: true,
    titleBarStyle: 'default',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  win.once('ready-to-show', () => {
    if (win.isMinimized()) win.restore();
    win.center();
    win.show();
    win.focus();
  });

  win.webContents.on('did-fail-load', (_e, code, desc, url) => {
    console.error('Main did-fail-load:', code, desc, url);
    win.loadURL('data:text/html,' + encodeURIComponent(`<h2>Load thất bại: ${code} - ${desc}</h2>`));
  });

  win.loadFile('index.html').catch(err => console.error('Main loadFile error:', err));
}

// ========== FACTORY CHUNG TẠO WINDOW CON ==========
function createChild({ width, height, html, modal = true }) {
  const w = new BrowserWindow({
    width, height,
    parent: win,
    modal,
    show: false,
    icon: runtimeIcon(),
    frame: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });
  w.setMenu(null);
  w.once('ready-to-show', () => { w.show(); w.focus(); });
  w.webContents.on('did-fail-load', (_e, c, d, u) => {
    console.error(`Child(${html}) did-fail-load:`, c, d, u);
    w.loadURL('data:text/html,' + encodeURIComponent(`<h2>Load ${html} thất bại: ${c} - ${d}</h2>`));
  });
  w.loadFile(html).catch(err => console.error(`Child(${html}) loadFile error:`, err));
  return w;
}

// ========== CỬA SỔ CON ==========
function createSettingsWindow() {
  if (settingsWin && !settingsWin.isDestroyed()) { settingsWin.show(); settingsWin.focus(); return; }
  settingsWin = createChild({ width: 650, height: 800, html: 'settings.html' });
}

function createBitLockerWindow() {
  if (bitlockerWin && !bitlockerWin.isDestroyed()) { bitlockerWin.show(); bitlockerWin.focus(); return; }
  bitlockerWin = createChild({ width: 860, height: 700, html: 'bitlocker.html' });
}

function createActivationWindow() {
  if (activationWin && !activationWin.isDestroyed()) { activationWin.show(); activationWin.focus(); return; }
  activationWin = createChild({ width: 900, height: 760, html: 'activation.html' });
}

// ========== BOOTSTRAP ==========
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.whenReady().then(() => {
    app.setAppUserModelId('com.baobeo.bbhelpdesktools');
    createWindow();
  });

  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
  app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
}

// ========== IPC ==========
ipcMain.on('open-settings-window', () => createSettingsWindow());
ipcMain.on('open-bitlocker-window', () => createBitLockerWindow());
ipcMain.on('open-activation-window', () => createActivationWindow());

// Mở dialog chọn thư mục (để preload.openDirectory() hoạt động)
ipcMain.handle('dialog:openDirectory', async () => {
  const result = await dialog.showOpenDialog({
    properties: ['openDirectory', 'createDirectory']
  });
  return result.canceled ? null : result.filePaths[0];
});

// Trả về thư mục backup hiện tại
ipcMain.handle('backup:get-dir', async () => {
  return backupDir;
});

// Cập nhật thư mục backup và broadcast cho mọi cửa sổ
ipcMain.on('backup:set-dir', (_e, dir) => {
  if (typeof dir === 'string' && dir.trim()) {
    backupDir = dir.trim();
    BrowserWindow.getAllWindows().forEach(w => {
      try { w.webContents.send('backup:dir-updated', backupDir); } catch {}
    });
  }
});

// === IPC Handlers cho Cửa sổ Settings và các chức năng khác ===

ipcMain.handle('get-all-settings', async () => {
    const commands = {
        uac: `(Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "EnableLUA").EnableLUA`,
        firewall: `(Get-NetFirewallProfile -Name Public).Enabled`,
        windowsUpdate: `(Get-Service -Name wuauserv).StartType`,
        explorer: `(Get-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" -Name "LaunchTo" -ErrorAction SilentlyContinue).LaunchTo`,
        search: `(Get-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Search" -Name "SearchboxTaskbarMode" -ErrorAction SilentlyContinue).SearchboxTaskbarMode`,
        powerMode: `(powercfg /getactivescheme).Split(' ')[3]`
    };

    let settings = {};
    for (const key in commands) {
        const result = await runPowerShellCommand(commands[key]);
        settings[key] = result.data;
    }
    return settings;
});

ipcMain.handle('set-toggle-status', (e, { feature, isEnabled }) => {
  let command;
  const resourcesPath = app.isPackaged ? path.join(process.resourcesPath, 'resources') : path.join(__dirname, 'resources');
  const wubPath = path.join(resourcesPath, 'Wub_x64.exe');

  switch (feature) {
    case 'uac': command = `Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "EnableLUA" -Value ${isEnabled ? 1 : 0}`; break;
    case 'firewall': command = `Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled "${isEnabled ? 'True' : 'False'}"`; break;
    case 'windows-update':
      const argument = isEnabled ? '/E' : '/D';
      return runExeCommand(`"${wubPath}" ${argument}`);
    case 'explorer': command = `Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" -Name "LaunchTo" -Value ${isEnabled ? 1 : 2}`; break;
    case 'search': command = `Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Search" -Name "SearchboxTaskbarMode" -Value ${isEnabled ? 1 : 2}`; break;
  }
  return runPowerShellCommand(command);
});

ipcMain.handle('set-power-mode', (e, { mode }) => {
    const powerPlanGuids = {
        balanced: '381b4222-f694-41f0-9685-ff5bb260df2e',
        powerSaver: 'a1841308-3541-4fab-bc81-f71556f20b4a',
        highPerformance: '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
    };
    const guid = powerPlanGuids[mode];
    return runPowerShellCommand(`powercfg /setactive ${guid}`);
});

ipcMain.handle('set-timeout', (e, { type, mode, minutes }) => {
    return runPowerShellCommand(`powercfg /change ${type}-timeout-${mode} ${minutes}`);
});

ipcMain.handle('set-computer-name', (e, name) => runPowerShellCommand(`Rename-Computer -NewName "${name}" -Force`));
ipcMain.handle('set-workgroup', (e, name) => runPowerShellCommand(`Add-Computer -WorkGroupName "${name}" -Force`));
ipcMain.handle('set-timezone', (e, tz) => runPowerShellCommand(`Set-Timezone -Id "${tz}"`));

ipcMain.handle('get-system-info', async () => {
  const psCommand = `
    $ErrorActionPreference = "SilentlyContinue";$output = [PSCustomObject]@{ cpu = $null; motherboard = $null; memory = $null; gpu = @(); os = $null; network = @(); drives = @() };$proc = Get-CimInstance -ClassName Win32_Processor; if ($proc) { $socketCount = ($proc.SocketDesignation | Group-Object | Measure-Object).Count; $output.cpu = @{ Name = $proc[0].Name; Socket = $socketCount; Cores = $proc[0].NumberOfCores; Threads = $proc[0].NumberOfLogicalProcessors; SocketDesignation = $proc[0].SocketDesignation } };$mb = Get-CimInstance -ClassName Win32_BaseBoard; $bios = Get-CimInstance -ClassName Win32_BIOS; if ($mb -and $bios) { $output.motherboard = @{ Model = "$($mb.Manufacturer) $($mb.Product)"; Version = $mb.Version; SerialNumber = $mb.SerialNumber; BiosVersion = $bios.SMBIOSBIOSVersion; BiosReleaseDate = $bios.ReleaseDate.ToString('yyyy-MM-dd') } };$memSlots = Get-CimInstance -ClassName Win32_PhysicalMemory; $memArray = Get-CimInstance -ClassName Win32_PhysicalMemoryArray; if ($memSlots -and $memArray) { $memSticks = @(); foreach($stick in $memSlots) { $memSticks += [PSCustomObject]@{ Size = [math]::Round($stick.Capacity / 1GB); Type = switch ($stick.SMBIOSMemoryType) { 20 { "DDR" } 21 { "DDR2" } 22 { "DDR2 FB-DIMM" } 24 { "DDR3" } 26 { "DDR4" } 34 { "DDR5" } default { "RAM" } }; ModuleManuf = $stick.Manufacturer; Speed = $stick.ConfiguredClockSpeed; PartNumber = $stick.PartNumber } }; $output.memory = @{ TotalSlots = $memArray.MemoryDevices; UsedSlots = $memSlots.Count; Sticks = $memSticks } };$gpus = Get-CimInstance -ClassName Win32_VideoController; if ($gpus) { foreach($gpu in $gpus) { $output.gpu += @{ Name = $gpu.Name } } };$os = Get-CimInstance -ClassName Win32_OperatingSystem; if ($os) { $output.os = @{ Name = $os.Caption; Version = $os.Version } };$disks = Get-CimInstance -ClassName Win32_DiskDrive; if ($disks) { foreach($disk in $disks) { $output.drives += @{ Model = $disk.Model; Size = [math]::Round($disk.Size / 1GB); Interface = $disk.InterfaceType } } };if (-not (Get-Variable output -Scope 0 -ErrorAction SilentlyContinue)) { $output = [ordered]@{} }; if ($output -is [System.Collections.IDictionary]) { if (-not $output.Contains('network')) { $output['network'] = @() } } else { if (-not $output.PSObject.Properties['network']) { $output | Add-Member -NotePropertyName network -NotePropertyValue @() } }; if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) { $net = Get-NetAdapter -Physical | Sort-Object ifIndex; foreach ($n in $net) { $ipv4 = $null; $gateway = $null; $dns = $null; if ($n.Status -eq 'Up') { $ipv4 = (Get-NetIPAddress -InterfaceIndex $n.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -and $_.IPAddress -notmatch '^169\.254\.' -and $_.IPAddress -ne '0.0.0.0' -and $_.AddressState -eq 'Preferred' } | Select-Object -ExpandProperty IPAddress) -join ', '; $gateway = (Get-NetRoute -InterfaceIndex $n.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop); $dns = (Get-DnsClientServerAddress -InterfaceIndex $n.ifIndex -AddressFamily IPv4,IPv6 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | Select-Object -Unique) -join ', ' }; $output.network += [pscustomobject]@{ Name = $n.InterfaceDescription; Status = $n.Status; LinkSpeed = $n.LinkSpeed; MacAddress = $n.MacAddress; IPv4 = $ipv4; Gateway = $gateway; DNSServers = $dns } } } else { $phy = Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter }; $cfg = Get-CimInstance Win32_NetworkAdapterConfiguration; foreach ($a in $phy) { $c = $cfg | Where-Object { $_.Index -eq $a.Index }; $connected = ($a.NetConnectionStatus -eq 2) -and $c -and $c.IPEnabled; $speedMbps = if ($a.Speed) { [math]::Round($a.Speed/1MB,0) } else { $null }; $mac = if ($c) { $c.MACAddress } else { $a.MACAddress }; $ipv4 = if ($connected) { ($c.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -notmatch '^169\.254\.' -and $_ -ne '0.0.0.0' } | Select-Object -Unique) -join ', ' } else { $null }; $gateway = if ($connected -and $c.DefaultIPGateway) { ($c.DefaultIPGateway | Select-Object -First 1) } else { $null }; $dns = if ($connected -and $c.DNSServerSearchOrder) { ($c.DNSServerSearchOrder | Select-Object -Unique) -join ', ' } else { $null }; $output.network += [pscustomobject]@{ Name = $a.Name; Status = if ($connected) { 'Up' } else { 'Disconnected' }; LinkSpeed = if ($speedMbps) { "$speedMbps Mbps" } else { $null }; MacAddress = $mac; IPv4 = $ipv4; Gateway = $gateway; DNSServers = $dns } } };return $output | ConvertTo-Json -Depth 5 -Compress
  `;
  return new Promise((resolve, reject) => {
    const ps = spawn('powershell.exe', ['-NoProfile', '-Command', '-']);
    let stdoutData = '', stderrData = '';
    ps.stdin.write(psCommand); ps.stdin.end();
    ps.stdout.on('data', (data) => { stdoutData += data.toString(); });
    ps.stderr.on('data', (data) => { stderrData += data.toString(); });
    ps.on('close', (code) => {
      if (code !== 0) { console.error(stderrData); return reject(new Error(stderrData)); }
      resolve(stdoutData);
    });
    ps.on('error', (err) => { console.error('Failed to start PowerShell process.', err); reject(err); });
  });
});



// Hàm tạo cửa sổ Thiết lập Mạng
function createNetworkWindow() {
  if (networkWin && !networkWin.isDestroyed()) { networkWin.show(); networkWin.focus(); return; }

  networkWin = new BrowserWindow({
    width: 850,
    height: 800,
    parent: win,
    modal: true,
    show: false,
    icon: runtimeIcon(),                // << thêm icon
    frame: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  networkWin.setMenu(null);
  networkWin.once('ready-to-show', () => { networkWin.show(); networkWin.focus(); });
  networkWin.loadFile('network.html');
}


// Lắng nghe lệnh mở cửa sổ mạng
ipcMain.on('open-network-window', () => createNetworkWindow());

// ======================== NETWORK IPC =========================

// List physical adapters
ipcMain.handle('get-network-adapters', async () => {
  const ps = `
try {
  $adapters = Get-NetAdapter -Physical | Select-Object ifIndex,Name,InterfaceDescription,Status,AdminStatus,MacAddress,LinkSpeed
  @($adapters) | ConvertTo-Json -Depth 4
} catch { Write-Error $_.Exception.Message; exit 1 }
  `;
  return await runPowerShellCommand(ps);
});

// Trả chi tiết adapter; vẫn trả object tối thiểu khi Disabled
ipcMain.handle('get-adapter-details', async (_e, ifIndex) => {
  if (!ifIndex || ifIndex === 'undefined') {
    return { success: false, message: 'Invalid InterfaceIndex' };
  }

  const ps = `
param([int]$Idx)
try {
  $ad = Get-NetAdapter -InterfaceIndex $Idx -ErrorAction SilentlyContinue
  if (-not $ad) { throw "Adapter not found" }

  # Các lệnh dưới đây có thể null khi adapter Disabled -> dùng SilentlyContinue
  $ip     = Get-NetIPConfiguration       -InterfaceIndex $Idx -ErrorAction SilentlyContinue
  $iface  = Get-NetIPInterface           -InterfaceIndex $Idx -ErrorAction SilentlyContinue
  $dnsInf = Get-DnsClientServerAddress   -InterfaceIndex $Idx -ErrorAction SilentlyContinue

  $dhcp = $false
  if ($iface) { $dhcp = ($iface.Dhcp -eq 'Enabled') }

  $dnsAssign = $null
  if ($dnsInf) {
    $origin = ($dnsInf | Select-Object -First 1).AddressOrigin
    if ($origin -eq 'Dhcp')      { $dnsAssign = 'Automatic (DHCP)' }
    elseif ($origin -eq 'Manual'){ $dnsAssign = 'Manual' }
    elseif ($origin)             { $dnsAssign = $origin }
  }

  # Thông tin Wi-Fi (nếu là adapter 802.11)
  $ssid = $null; $protocol = $null
  if ($ad.MediaType -eq '802.11') {
    $text = netsh wlan show interfaces | Out-String
    $ssid     = ($text -split "\\r?\\n" | Where-Object { $_ -match '^\\s*SSID\\s*:\\s*.+$' }   | Select-Object -First 1) -replace '^\\s*SSID\\s*:\\s*',''
    $protocol = ($text -split "\\r?\\n" | Where-Object { $_ -match '^\\s*Radio type\\s*:\\s*.+$' } | Select-Object -First 1) -replace '^\\s*Radio type\\s*:\\s*',''
  }

  # Dựng object trả về (có thể có các trường null khi Disabled)
  [pscustomobject]@{
    IfIndex        = $Idx
    Name           = $ad.Name
    InterfaceDesc  = $ad.InterfaceDescription
    Status         = $ad.Status
    MacAddress     = $ad.MacAddress
    LinkSpeed      = $ad.LinkSpeed
    IPAssignment   = $(if ($dhcp) { 'Automatic (DHCP)' } else { 'Manual' })
    DnsAssignment  = $dnsAssign
    IPv4DNS        = $ip.DnsServer.ServerAddresses
    IPv4Address    = ($ip.IPv4Address | ForEach-Object { $_.IPv4Address })
    IPv4Gateway    = $ip.IPv4DefaultGateway.NextHop
    SSID           = $ssid
    Protocol       = $protocol
    DriverInfo     = $ad.DriverInformation
  } | ConvertTo-Json -Depth 5 -Compress

} catch {
  Write-Error $_.Exception.Message
  exit 1
}
`;

  return await runPowerShellCommand(`& { ${ps} } -Idx ${Number(ifIndex)}`);
});



// Bật / Tắt card mạng: payload = { ifIndex: number, isEnabled: boolean }
ipcMain.handle('set-adapter-state', async (_e, payload) => {
  try {
    const idx = Number(payload?.ifIndex);
    if (!Number.isFinite(idx)) return { success: false, message: 'Invalid ifIndex' };

    const enablePS = payload.isEnabled ? '$true' : '$false'; // map JS -> PS

    const ps = `
param([int]$Idx, [bool]$Enable)
$ad = Get-NetAdapter -InterfaceIndex $Idx -ErrorAction Stop
if ($Enable) {
  Enable-NetAdapter  -Name $ad.Name -Confirm:$false -ErrorAction Stop | Out-Null
} else {
  Disable-NetAdapter -Name $ad.Name -Confirm:$false -ErrorAction Stop | Out-Null
}
"OK"
`;
    // truyền tham số đúng kiểu
    return await runPowerShellCommand(`& { ${ps} } -Idx ${idx} -Enable ${enablePS}`);
  } catch (err) {
    return { success: false, message: String(err?.message || err) };
  }
});




// payload = { interfaceIndex, ipAddress, subnetMask, gateway?, dnsServers?[] }
ipcMain.handle('set-static-ip', async (_e, p) => {
  try {
    const idx  = Number(p?.interfaceIndex);
    const ip   = String(p?.ipAddress || '').trim();
    const mask = String(p?.subnetMask || '').trim();
    const gw   = (p?.gateway && String(p.gateway).trim()) ? String(p.gateway).trim() : 'none';
    const dns  = Array.isArray(p?.dnsServers) ? p.dnsServers.filter(Boolean).map(s => String(s).trim()) : [];

    if (!Number.isFinite(idx)) {
      return { success:false, message:'Invalid interfaceIndex' };
    }

    // ⚡ Trường hợp chỉ muốn set DNS
    if (!ip && !mask && dns.length > 0) {
      const ps = `
param([int]$Idx,[string[]]$Dns)
try{
  $ad    = Get-NetAdapter -InterfaceIndex $Idx -ErrorAction Stop
  $alias = $ad.InterfaceAlias

  # Đặt lại DNS theo danh sách
  netsh interface ipv4 set dns name="$alias" static $($Dns[0]) primary
  if ($Dns.Count -gt 1) {
    for ($i=1; $i -lt $Dns.Count; $i++) {
      netsh interface ipv4 add dns name="$alias" address=$($Dns[$i]) index=($i+1)
    }
  }
  'OK'
} catch { throw $_.Exception.Message }
`;
      return await runPowerShellCommand(`& { ${ps} } -Idx ${idx} -Dns @(${dns.map(d=>`"${d}"`).join(',')})`);
    }

    // ⚡ Trường hợp set IP tĩnh đầy đủ (có ip + mask)
    if (!ip || !mask) {
      return { success:false, message:'Missing ipAddress or subnetMask' };
    }

    const ps = `
param([int]$Idx,[string]$Ip,[string]$Mask,[string]$Gw,[string[]]$Dns)
try{
  $ad    = Get-NetAdapter -InterfaceIndex $Idx -ErrorAction Stop
  $alias = $ad.InterfaceAlias

  netsh interface ipv4 delete address name="$alias" addr=all
  netsh interface ipv4 delete route   0.0.0.0/0 name="$alias"

  netsh interface ipv4 set address name="$alias" static $Ip $Mask $Gw

  if ($Dns -and $Dns.Count -gt 0) {
    netsh interface ipv4 set dns name="$alias" static $($Dns[0]) primary
    if ($Dns.Count -gt 1) {
      for ($i=1; $i -lt $Dns.Count; $i++) {
        netsh interface ipv4 add dns name="$alias" address=$($Dns[$i]) index=($i+1)
      }
    }
  } else {
    netsh interface ipv4 set dns name="$alias" source=dhcp
  }
  'OK'
} catch { throw $_.Exception.Message }
`;
    return await runPowerShellCommand(`& { ${ps} } -Idx ${idx} -Ip "${ip}" -Mask "${mask}" -Gw "${gw}" -Dns @(${dns.map(d=>`"${d}"`).join(',')})`);
  } catch (err) {
    return { success:false, message:String(err?.message || err) };
  }
});


// Bật DHCP + dọn sạch gateway tĩnh + renew
ipcMain.handle('set-dynamic-ip', async (_e, ifIndex) => {
  try {
    const idx = Number(ifIndex);
    if (!Number.isFinite(idx)) {
      return { success: false, message: 'Invalid interfaceIndex' };
    }

    const ps = `
param([int]$Idx)
try {
  $ad = Get-NetAdapter -InterfaceIndex $Idx -ErrorAction Stop

  # 1) Bật DHCP cho IPv4 + DNS tự động (PersistentStore)
  Set-NetIPInterface -InterfaceIndex $Idx -AddressFamily IPv4 -Dhcp Enabled -ErrorAction Stop
  Set-DnsClientServerAddress -InterfaceIndex $Idx -ResetServerAddresses -ErrorAction Stop

  # 2) Xoá mọi default route tĩnh (0.0.0.0/0) còn lưu
  Get-NetRoute -InterfaceIndex $Idx -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

  # 3) Xoá các IPv4 tĩnh còn sót (PrefixOrigin = Manual)
  Get-NetIPAddress -InterfaceIndex $Idx -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.PrefixOrigin -eq 'Manual' } |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

  # 4) Renew địa chỉ ngay
  ipconfig /renew "$($ad.InterfaceAlias)" | Out-Null

  'OK'
}
catch { throw $_.Exception.Message }
`;

    return await runPowerShellCommand(`& { ${ps} } -Idx ${idx}`);
  } catch (err) {
    return { success: false, message: String(err?.message || err) };
  }
});


// ======================== BLOATWARE IPC =======================

function createBloatwareWindow() {
  if (bloatwareWin && !bloatwareWin.isDestroyed()) { bloatwareWin.show(); bloatwareWin.focus(); return; }

  bloatwareWin = new BrowserWindow({
    width: 600,
    height: 750,
    parent: win,
    modal: true,
    show: false,
    icon: runtimeIcon(),                // << thêm icon
    frame: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  bloatwareWin.setMenu(null);
  bloatwareWin.once('ready-to-show', () => { bloatwareWin.show(); bloatwareWin.focus(); });
  bloatwareWin.loadFile('bloatware.html');
}



ipcMain.on('open-bloatware-window', () => {
  createBloatwareWindow();
});

ipcMain.handle('get-installed-apps', async () => {
  const ps = `
try {
  Get-AppxPackage -AllUsers |
    Select-Object Name, PackageFamilyName |
    ConvertTo-Json -Depth 3
} catch { Write-Error $_.Exception.Message; exit 1 }
  `;
  return await runPowerShellCommand(ps);
});

ipcMain.handle('get-installed-win32', async () => {
  const ps = `
$paths = @(
 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
 'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
)
Get-ItemProperty $paths -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName } |
  Select-Object DisplayName, DisplayVersion, Publisher |
  Sort-Object DisplayName |
  ConvertTo-Json -Depth 3
`;
  return await runPowerShellCommand(ps);
});

// Gỡ theo danh sách pattern (hỗ trợ wildcard * ? ở Name/PFN)
ipcMain.handle('remove-bloatware', async (_e, patterns) => {
  if (!Array.isArray(patterns) || patterns.length === 0)
    return { success: true, message: 'Không có ứng dụng nào được chọn.' };

  const items = patterns.map(p => `'${String(p).replace(/'/g,"''")}'`).join(',');
  const ps = `
param([string[]]$Patterns)
try {
  foreach ($pat in $Patterns) {
    $pkgs = Get-AppxPackage -AllUsers |
      Where-Object { $_.Name -like $pat -or $_.PackageFamilyName -like $pat }
    foreach ($p in $pkgs) {
      Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction SilentlyContinue
    }
  }
  "DONE"
} catch { Write-Error $_.Exception.Message; exit 1 }
  `;
  return await runPowerShellCommand(`& { ${ps} } -Patterns @(${items})`);
});

// ======================== BITLOCKER IPC =======================

ipcMain.handle('bitlocker:is-admin', async () => {
  const ps = `
  $id = [System.Security.Principal.WindowsIdentity]::GetCurrent();
  $p = New-Object System.Security.Principal.WindowsPrincipal($id);
  if ($p.IsInRole([System.Security.Principal.WindowsBuiltinRole]::Administrator)) { 'True' } else { 'False' }`;
  const r = await runPowerShellCommand(ps);
  return String(r?.data || '').trim().toLowerCase() === 'true';
});

ipcMain.handle('bitlocker:scan', async () => {
  const ps = `
try {
  $vols = Get-Volume | Where-Object { $_.DriveLetter -match '^[A-Z]$' }
  $out = foreach ($v in $vols) {
    $mp = "$($v.DriveLetter):"
    $bl = $null
    try { $bl = Get-BitLockerVolume -MountPoint $mp -ErrorAction Stop } catch {}
    [pscustomobject]@{
      Drive               = $mp
      Label               = $v.FileSystemLabel
      FileSystem          = $v.FileSystem
      SizeGB              = [math]::Round(($v.Size/1GB),1)
      ProtectionStatus    = if ($bl) { $bl.ProtectionStatus } else { 'Off' }
      LockStatus          = if ($bl) { $bl.LockStatus } else { $null }
      EncryptionPercentage= if ($bl) { [int]$bl.EncryptionPercentage } else { 0 }
      AutoUnlockEnabled   = if ($bl) { [bool]$bl.AutoUnlockEnabled } else { $false }
      IsBitLocker         = if ($bl) { $bl.ProtectionStatus -eq 'On' } else { $false }
    }
  }
  $out | ConvertTo-Json -Depth 4 -Compress
} catch { Write-Error $_.Exception.Message; exit 1 }
`;
  const r = await runPowerShellCommand(ps);
  if (!r.success) return r;
  const data = JSON.parse(r.data || '[]');
  return { success:true, data };
});

ipcMain.handle('bitlocker:backup', async (_e, { drives, outputDir }) => {
  if (!Array.isArray(drives) || drives.length === 0) {
    return { success: false, message: 'Không có ổ nào được chọn.' };
  }
  if (!outputDir) {
    return { success: false, message: 'Thiếu thư mục lưu.' };
  }

  // Escape cho PowerShell (dùng khi truyền tham số qua dòng lệnh)
  const escPS = s => String(s).replace(/`/g, '``').replace(/"/g, '`"');

  const list  = drives.map(d => `"${String(d).replace(/"/g, '`"')}"`).join(',');
  const escDir = escPS(outputDir);

  // --- Script PowerShell: KHÔNG dùng `\`r\`n`, thay bằng [Environment]::NewLine ---
  const ps = `
param([string[]]$Drives,[string]$OutDir)
try {
  if (-not (Test-Path -LiteralPath $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
  }

  $files = @()
  $nl = [System.Environment]::NewLine

  foreach ($d in $Drives) {
    $text = (manage-bde -protectors -get $d) | Out-String
    $matches = [regex]::Matches($text, '([0-9]{6}-){7}[0-9]{6}')
    $rps = foreach ($m in $matches) { $m.Value }

    $fn = Join-Path $OutDir ("BitLockerKey-$($d.TrimEnd(':'))-{0:yyyyMMdd-HHmmss}.txt" -f (Get-Date))
    $content = "Drive: $d$nlRecovery Password(s):$nl" + ($rps -join $nl)

    Set-Content -LiteralPath $fn -Value $content -Encoding UTF8
    $files += $fn
  }

  [pscustomobject]@{ Files = $files } | ConvertTo-Json -Compress
} catch {
  Write-Error $_.Exception.Message
  exit 1
}
`;

  // Ghi script ra file tạm và chạy bằng -File (tránh rối escape)
  const tmp = path.join(os.tmpdir(), 'backup-bitlocker.ps1');
  fs.writeFileSync(tmp, ps, 'utf8');

  const r = await runPowerShellCommand(
    `powershell -NoProfile -ExecutionPolicy Bypass -File "${tmp}" -Drives @(${list}) -OutDir "${escDir}"`
  );

  if (!r.success) return r;

  try {
    const parsed = JSON.parse(r.data || '{}');
    return { success: true, files: parsed.Files || [] };
  } catch {
    return { success: true, files: [] };
  }
});


ipcMain.handle('bitlocker:disable', async (_e, drives) => {
  if (!Array.isArray(drives) || drives.length === 0)
    return { success:false, message:'Không có ổ nào được chọn.' };

  const items = drives.map(d => `"${String(d).replace(/"/g,'`"')}"`).join(',');
  const ps = `
param([string[]]$Drives)
try {
  foreach ($d in $Drives) {
    try {
      Disable-BitLocker -MountPoint $d -ErrorAction Stop | Out-Null
    } catch {
      # fallback cho các máy không có module BitLocker
      manage-bde -off $d | Out-Null
    }
  }
  "OK"
} catch { Write-Error $_.Exception.Message; exit 1 }
`;
  const r = await runPowerShellCommand(`& { ${ps} } -Drives @(${items})`);
  return r;
});

// ======================== ACTIVATION IPC =======================
ipcMain.handle('activation:get-status', async () => {
  const ps = `
$ErrorActionPreference='SilentlyContinue'

# ===================== WINDOWS =====================
function Get-WindowsActivation {
  $winAppId = '55c92734-d682-4d71-983e-d6ec3f16059f'
  $p = Get-CimInstance SoftwareLicensingProduct -ErrorAction SilentlyContinue |
       Where-Object { $_.ApplicationID -eq $winAppId -and $_.PartialProductKey } |
       Sort-Object LicenseStatus -Descending | Select-Object -First 1
  if (-not $p) { return $null }

  $statusMap = @{
    0='Unlicensed';1='Licensed';2='OOB Grace';3='Non-Genuine';4='Notification';5='Extended Grace'
  }

  $xpr = (cscript.exe //Nologo "$env:SystemRoot\\System32\\slmgr.vbs" /xpr 2>&1 | Out-String).Trim()
  if (-not $xpr) {
    if ([double]$p.GracePeriodRemaining -gt 0) {
      $ts=[TimeSpan]::FromSeconds([double]$p.GracePeriodRemaining)
      $xpr = 'Grace remaining: ' + $ts.ToString()
    } else { $xpr = 'N/A' }
  }

  $chan = $p.ProductKeyChannel
  if (-not $chan) {
    $d = ($p.Description | Out-String)
    if ($d -match '(?i)VOLUME_KMSCLIENT'){ $chan='Volume KMS Client' }
    elseif ($d -match '(?i)RETAIL'){ $chan='Retail' }
    elseif ($d -match '(?i)MAK'){ $chan='MAK' }
    elseif ($d -match '(?i)OEM'){ $chan='OEM' }
    else { $chan='N/A' }
  }

  [pscustomobject]@{
    Name              = $p.Name
    LicenseStatus     = $statusMap[[int]$p.LicenseStatus]
    ActivationID      = $p.ID
    ProductKeyChannel = $chan
    ExpirationInfo    = $xpr
    PartialProductKey = $p.PartialProductKey
  }
}

# ===================== OFFICE =====================
function Get-OfficeInstances {
  $pf   = $env:ProgramFiles
  $pf86 = [Environment]::GetFolderPath('ProgramFilesX86')

  $cands = @()
  if ($pf) {
    $cands += (Join-Path $pf   'Microsoft Office\\root\\Office16\\OSPP.VBS')
    $cands += (Join-Path $pf   'Microsoft Office\\Office16\\OSPP.VBS')
  }
  if ($pf86) {
    $cands += (Join-Path $pf86 'Microsoft Office\\root\\Office16\\OSPP.VBS')
    $cands += (Join-Path $pf86 'Microsoft Office\\Office16\\OSPP.VBS')
  }
  $cands = $cands | Where-Object { Test-Path $_ }
  if ($cands.Count -gt 0) { return ($cands | Select-Object -Unique) }

  $roots = @()
  if ($pf)   { $roots += (Join-Path $pf   'Microsoft Office') }
  if ($pf86) { $roots += (Join-Path $pf86 'Microsoft Office') }

  $ospp = @()
  foreach ($r in $roots) {
    Get-ChildItem -LiteralPath $r -Recurse -Filter 'OSPP.VBS' -ErrorAction SilentlyContinue |
      ForEach-Object { $ospp += $_.FullName }
  }
  return ($ospp | Select-Object -Unique)
}

function Get-OsppOutput([string]$ospp) {
  $pat = '(?im)^\\s*LICENSE NAME:\\s*.+$'
  $o1 = & "$env:SystemRoot\\System32\\cscript.exe"  //Nologo "$ospp" /dstatusall 2>&1 | Out-String
  if ($o1 -match $pat) { return $o1 }
  $o2 = & "$env:SystemRoot\\SysWOW64\\cscript.exe" //Nologo "$ospp" /dstatusall 2>&1 | Out-String
  if ($o2 -match $pat) { return $o2 }
  $o3 = & "$env:SystemRoot\\System32\\cscript.exe"  //Nologo "$ospp" /dstatus 2>&1 | Out-String
  if ($o3 -match $pat) { return $o3 }
  $o4 = & "$env:SystemRoot\\SysWOW64\\cscript.exe" //Nologo "$ospp" /dstatus 2>&1 | Out-String
  return $o4
}

function Infer-Channel([string]$desc){
  if ($desc -match '(?i)VOLUME_KMSCLIENT') { return 'Volume KMS Client' }
  if ($desc -match '(?i)RETAIL')           { return 'Retail' }
  if ($desc -match '(?i)MAK')              { return 'MAK' }
  if ($desc -match '(?i)OEM')              { return 'OEM' }
  return 'N/A'
}

function Rank([string]$s){
  if ($s -match '---LICENSED---')      { return 3 }
  if ($s -match '---NOTIFICATIONS---') { return 2 }
  if ($s -match '---UNLICENSED---')    { return 1 }
  return 0
}

function Get-OfficeActivation {
  $list = @()
  $paths = Get-OfficeInstances
  if (-not $paths -or $paths.Count -eq 0) { return @() }

  foreach ($p in $paths) {
    $txt = Get-OsppOutput $p

    # /dstatus(all) có thể trả nhiều block cho nhiều SKU
    $blocks = [regex]::Split($txt,'(?m)^\\s*-{5,}\\s*$|(?ms)\\r?\\n\\s*\\r?\\n') |
              Where-Object { $_ -and ($_.Trim() -ne '') }

    foreach ($b in $blocks) {
      $prod  = ([regex]::Match($b,'(?im)^\\s*(SKU ID|PRODUCT ID):\\s*(.+)$').Groups[2].Value).Trim()
      $name  = ([regex]::Match($b,'(?im)^\\s*LICENSE NAME:\\s*(.+)$').Groups[1].Value).Trim()
      $desc  = ([regex]::Match($b,'(?im)^\\s*LICENSE DESCRIPTION:\\s*(.+)$').Groups[1].Value).Trim()
      $stat  = ([regex]::Match($b,'(?im)^\\s*LICENSE STATUS:\\s*(.+)$').Groups[1].Value).Trim()
      $chan  = ([regex]::Match($b,'(?im)^\\s*PRODUCT KEY CHANNEL:\\s*(.+)$').Groups[1].Value).Trim()
      if (-not $chan) { $chan = (Infer-Channel $desc) }
      $exp1  = ([regex]::Match($b,'(?im)^\\s*Activation Expiration:\\s*(.+)$').Groups[1].Value).Trim()
      $exp2  = ([regex]::Match($b,'(?im)^\\s*REMAINING GRACE:\\s*(.+)$').Groups[1].Value).Trim()
      $actId = ([regex]::Match($b,'(?im)^\\s*Activation ID:\\s*([A-F0-9-]{10,})$').Groups[1].Value).Trim()

      if ($name -or $stat -or $desc) {
        $list += [pscustomobject]@{
          Product            = if($prod){$prod}else{'N/A'}
          LicenseName        = $name
          LicenseDescription = $desc
          LicenseStatus      = if($stat){$stat}else{'N/A'}
          ActivationID       = if($actId){$actId}else{'N/A'}
          ProductKeyChannel  = if($chan){$chan}else{'N/A'}
          ExpirationInfo     = if($exp1){$exp1} elseif($exp2){$exp2} else {'N/A'}
          OsppPath           = $p
          Raw                = $b
          _Rank              = (Rank $stat)
          _Key               = if($prod){$prod}else{ ($name+'|'+$desc) }
        }
      }
    }
  }

  # Khử trùng lặp (tối ưu):
  # - Gom theo "họ" sản phẩm (bỏ đuôi Grace/Retail/edition)
  # - Chọn mục có trạng thái cao nhất (Licensed > Notifications > Unlicensed)
  # - Nếu bằng điểm, ưu tiên Retail > Grace > khác
  # - Nếu vẫn bằng, ưu tiên mục có ActivationID
  if ($list.Count -gt 1) {
    $best = foreach ($g in (
      $list | Group-Object -Property {
        $base = if ($_.Product -and $_.Product -ne 'N/A') { $_.Product }
                elseif ($_.LicenseName) { $_.LicenseName }
                else { $_.LicenseDescription }
        $base = $base -replace '(?i)[,_]?\s*(Grace|Retail)(\s*edition)?',''
        ($base -replace '\\s+',' ').Trim()
      }
    )) {
      $g.Group |
        Sort-Object -Property @(
          @{ Expression = { $_._Rank }; Descending = $true },
          @{ Expression = { if ($_.LicenseName -match '(?i)Retail') { 2 } elseif ($_.LicenseName -match '(?i)Grace') { 1 } else { 0 } }; Descending = $true },
          @{ Expression = { if ($_.ActivationID -and $_.ActivationID -ne 'N/A') { 1 } else { 0 } }; Descending = $true }
        ) |
        Select-Object -First 1
    }
    $list = $best
  }

  # Bỏ thuộc tính phụ trợ trước khi trả về
  $list | ForEach-Object {
    $_.PSObject.Properties.Remove('_Rank') | Out-Null
    $_.PSObject.Properties.Remove('_Key')  | Out-Null
  }
  return $list
}

[pscustomobject]@{
  windows = Get-WindowsActivation
  office  = Get-OfficeActivation
} | ConvertTo-Json -Depth 6 -Compress
  `;

  const r = await runPowerShellCommand(ps);
  if (!r.success) return { success:false, message:r.message || 'PowerShell error' };
  try { return { success:true, data: JSON.parse(r.data || '{}') }; }
  catch { return { success:true, data:{ windows:null, office:[] } }; }
});


ipcMain.handle('activation:run', async (_e, payload) => {
  // payload = { target:'windows'|'office', method:'HWID'|'TSforge'|'KMS38'|'OnlineKMS'|'Ohook', extra?:{} }
  try {
    const { target, method, extra = {} } = payload || {};

    // --- helper nhỏ để làm sạch input chuỗi (host, ids, port...) ---
    const safe = (v) => {
      if (typeof v !== 'string') return v;
      // chỉ cho phép chữ số, chữ cái, dấu chấm, gạch ngang, gạch dưới, 2 chấm (port)
      return v.trim().replace(/[^A-Za-z0-9.\-_:]/g, '');
    };

    // --- map phương pháp -> danh sách switch MAS ---
    const mapArgs = (t, m, x = {}) => {
      const opts = [];
      const ex = { ...x };

      // chuẩn hoá vài trường
      if (ex.kmsServer) ex.kmsServer = safe(ex.kmsServer);
      if (ex.kmsPort)   ex.kmsPort   = String(ex.kmsPort).replace(/[^\d]/g, '');

      if (t === 'windows') {
        if (m === 'HWID') {
          opts.push('/HWID');
          if (ex.noEditionChange) opts.push('/HWID-NoEditionChange');
        }
        if (m === 'TSforge') {
          opts.push('/Z-Windows');
          if (ex.tsMethod === 'SCID')  opts.push('/Z-SCID');
          if (ex.tsMethod === 'ZCID')  opts.push('/Z-ZCID');
          if (ex.tsMethod === 'KMS4k') opts.push('/Z-KMS4k');
          if (Array.isArray(ex.tsIds)) ex.tsIds.forEach(id => { id = safe(id); if (id) opts.push(`/Z-ID-${id}`); });
          if (ex.tsReset) opts.push('/Z-Reset');
        }
        if (m === 'KMS38') {
          opts.push('/KMS38');
          if (ex.noEditionChange)        opts.push('/KMS38-NoEditionChange');
          if (ex.kms38RemoveProtection)  opts.push('/KMS38-RemoveProtection');
        }
        if (m === 'OnlineKMS') {
          opts.push('/K-Windows');
          if (ex.noEditionChange) opts.push('/K-NoEditionChange');
          if (ex.noRenewalTask)  opts.push('/K-NoRenewalTask');
          if (ex.kmsServer)      opts.push(`/K-Server-${ex.kmsServer}`);
          if (ex.kmsPort)        opts.push(`/K-Port-${ex.kmsPort}`);
        }
      }

      if (t === 'office') {
        if (m === 'Ohook') {
          opts.push('/Ohook');
          if (ex.uninstallOhook) opts.push('/Ohook-Uninstall'); // nếu muốn gỡ Ohook
        }
        if (m === 'TSforge') {
          opts.push('/Z-Office');
          if (ex.tsMethod === 'SCID')  opts.push('/Z-SCID');
          if (ex.tsMethod === 'ZCID')  opts.push('/Z-ZCID');
          if (ex.tsMethod === 'KMS4k') opts.push('/Z-KMS4k');
          if (Array.isArray(ex.tsIds)) ex.tsIds.forEach(id => { id = safe(id); if (id) opts.push(`/Z-ID-${id}`); });
          if (ex.tsReset) opts.push('/Z-Reset');
        }
        if (m === 'OnlineKMS') {
          opts.push('/K-Office');
          if (ex.noEditionChange) opts.push('/K-NoEditionChange');
          if (ex.noRenewalTask)  opts.push('/K-NoRenewalTask');
          if (ex.kmsServer)      opts.push(`/K-Server-${ex.kmsServer}`);
          if (ex.kmsPort)        opts.push(`/K-Port-${ex.kmsPort}`);
        }
      }

      if (ex.silent) opts.push('/S'); // chỉ áp dụng khi chạy one-liner
      return opts.length ? opts : null;
    };

    const switches = mapArgs(target, method, extra);
    if (!switches) {
      return { success: false, message: 'Phương pháp/đích không hợp lệ.' };
    }

    // --- One-liner MAS: & ([ScriptBlock]::Create((irm https://get.activated.win))) <switches...>
    const ps = `
$ProgressPreference='SilentlyContinue';
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;
& ([ScriptBlock]::Create((irm https://get.activated.win))) ${switches.join(' ')}
`.trim();

    const result = await runPowerShellCommand(ps);

    return result.success
      ? { success: true, message: 'Đã chạy MAS.', raw: result.data }
      : { success: false, message: result.message || 'MAS thất bại.' };

  } catch (err) {
    return { success: false, message: String(err?.message || err) };
  }
});


// ======================== WIFI BACKUP IPC =======================
// ======================== WIFI (LIST) ========================
ipcMain.handle('wifi:list-profiles', async () => {
  const ps = `
$ErrorActionPreference='Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Dùng netsh 64-bit nếu tiến trình là 32-bit
$netsh = "$env:windir\\System32\\netsh.exe"
if (Test-Path "$env:windir\\Sysnative\\netsh.exe") { $netsh = "$env:windir\\Sysnative\\netsh.exe" }

# Thu tên profile theo nhiều locale
$raw = & $netsh wlan show profiles | Out-String
$names = @()
$patterns = @(
  '^\\s*All User Profile\\s*:\\s*(.+)$',
  '^\\s*Hồ sơ người dùng\\s*:\\s*(.+)$',
  '^\\s*Todos los perfiles de usuario\\s*:\\s*(.+)$',
  '^\\s*Tous les profils utilisateur\\s*:\\s*(.+)$'
)
foreach ($p in $patterns) {
  $names += [regex]::Matches($raw,$p,'IgnoreCase, Multiline') | ForEach-Object { $_.Groups[1].Value.Trim() }
}
$names = $names | Sort-Object -Unique

# Fallback: đọc tên từ XML ProgramData nếu netsh không trả
if ($names.Count -eq 0) {
  $ifaceDir = Join-Path $env:ProgramData 'Microsoft\\Wlansvc\\Profiles\\Interfaces'
  if (Test-Path $ifaceDir) {
    Get-ChildItem -Path $ifaceDir -Filter *.xml -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
      try { [xml]$x = Get-Content -LiteralPath $_.FullName -Encoding UTF8; if ($x.WLANProfile.name) { $names += $x.WLANProfile.name.Trim() } } catch {}
    }
    $names = $names | Sort-Object -Unique
  }
}

$out = foreach ($name in $names) {
  try {
    $detail = & $netsh wlan show profile name="$name" key=clear | Out-String
    $lines  = $detail -split "\\r?\\n"
    $ssid   = ($lines | ? { $_ -match '^\\s*SSID name\\s*:\\s*.+$' }      | select -First 1) -replace '^\\s*SSID name\\s*:\\s*',''
    if (-not $ssid) { $ssid = $name }
    $auth   = ($lines | ? { $_ -match '^\\s*Authentication\\s*:\\s*.+$' } | select -First 1) -replace '^\\s*Authentication\\s*:\\s*',''
    $cipher = ($lines | ? { $_ -match '^\\s*Cipher\\s*:\\s*.+$' }         | select -First 1) -replace '^\\s*Cipher\\s*:\\s*',''
    $key    = ($lines | ? { $_ -match '^\\s*Key Content\\s*:\\s*.+$' }    | select -First 1) -replace '^\\s*Key Content\\s*:\\s*',''
    [pscustomobject]@{
      Name=$name; SSID=($ssid).Trim(' ""'); Authentication=($auth).Trim();
      Cipher=($cipher).Trim(); Password=($key).Trim();
      HasPassword = -not [string]::IsNullOrWhiteSpace($key)
    }
  } catch {
    [pscustomobject]@{ Name=$name; SSID=$name; Authentication=$null; Cipher=$null; Password=$null; HasPassword=$false }
  }
}

# QUAN TRỌNG: luôn trả về JSON MẢNG (kể cả khi chỉ có 1 phần tử)
ConvertTo-Json -Depth 5 -Compress -InputObject $out
`;
  return await runPowerShellCommand(ps);
});


// ======================== WIFI (BACKUP) ========================
ipcMain.handle('wifi:backup', async (_e, payload) => {
  try {
    const { names, outputDir } = payload || {};
    if (!outputDir || !String(outputDir).trim()) return { success:false, message:'Thiếu thư mục lưu.' };

    const tmp = path.join(os.tmpdir(), 'backup-wifi.ps1');
    const ps = `
param([string[]]$Names,[string]$OutBase)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$netsh = "$env:windir\\System32\\netsh.exe"
if (Test-Path "$env:windir\\Sysnative\\netsh.exe") { $netsh = "$env:windir\\Sysnative\\netsh.exe" }

$ts  = Get-Date -Format 'yyyyMMdd-HHmmss'
$dir = Join-Path $OutBase ("WiFi-" + $ts)
if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

# Nếu không truyền danh sách -> lấy tất cả từ netsh
if (-not $Names -or $Names.Count -eq 0) {
  $raw = & $netsh wlan show profiles | Out-String
  $Names = [regex]::Matches($raw,'^\\s*All User Profile\\s*:\\s*(.+)$','IgnoreCase, Multiline') | % { $_.Groups[1].Value.Trim() }
}

$rows = foreach ($name in $Names) {
  try {
    $detail = & $netsh wlan show profile name="$name" key=clear | Out-String
    $lines  = $detail -split "\\r?\\n"
    $ssid   = ($lines | ? { $_ -match '^\\s*SSID name\\s*:\\s*.+$' }      | select -First 1) -replace '^\\s*SSID name\\s*:\\s*',''
    if (-not $ssid) { $ssid = $name }
    $auth   = ($lines | ? { $_ -match '^\\s*Authentication\\s*:\\s*.+$' } | select -First 1) -replace '^\\s*Authentication\\s*:\\s*',''
    $cipher = ($lines | ? { $_ -match '^\\s*Cipher\\s*:\\s*.+$' }         | select -First 1) -replace '^\\s*Cipher\\s*:\\s*',''
    $key    = ($lines | ? { $_ -match '^\\s*Key Content\\s*:\\s*.+$' }    | select -First 1) -replace '^\\s*Key Content\\s*:\\s*',''

    try { & $netsh wlan export profile name="$name" folder="$dir" key=clear | Out-Null } catch {}

    [pscustomobject]@{ Name=$name; SSID=($ssid).Trim(' ""'); Authentication=($auth).Trim(); Cipher=($cipher).Trim(); Password=($key).Trim() }
  } catch {
    [pscustomobject]@{ Name=$name; SSID=$name; Authentication=$null; Cipher=$null; Password=$null }
  }
}

# Ghi JSON/CSV
$jsonPath = Join-Path $dir 'wifi-backup.json'
$csvPath  = Join-Path $dir 'wifi-backup.csv'
ConvertTo-Json -Depth 5 -InputObject $rows | Set-Content -LiteralPath $jsonPath -Encoding UTF8
$rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

# Đóng gói
$xmls   = Get-ChildItem -LiteralPath $dir -Filter '*.xml' -ErrorAction SilentlyContinue | Select-Object -Expand FullName
$toZip  = @($jsonPath,$csvPath) + @($xmls | ? { Test-Path -LiteralPath $_ })
$zipPath = Join-Path $OutBase ("WiFi-$ts.zip")
if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
Compress-Archive -Path $toZip -DestinationPath $zipPath -Force

Remove-Item -LiteralPath $dir -Recurse -Force
[pscustomobject]@{ ZipFile = $zipPath; Count = ($rows | Measure-Object).Count } | ConvertTo-Json -Compress
`;
    fs.writeFileSync(tmp, ps, 'utf8');

    const safe = s => String(s||'').replace(/`/g,'``').replace(/"/g,'`"');
    const cmd  = `powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File "${tmp}" -OutBase "${safe(outputDir)}" -Names @(${(names||[]).map(n=>`"${safe(n)}"`).join(',')})`;
    const r = await runPowerShellCommand(cmd);
    try { fs.unlinkSync(tmp) } catch {}

    if (!r?.success) return r;

    // parse JSON để lấy ZipFile/Count, rồi trả về theo shape mà UI đang đọc
    let zip = '', count = 0;
    try {
      const parsed = JSON.parse(r.data || '{}');
      zip   = parsed.ZipFile || parsed.zipFile || '';
      count = parsed.Count   ?? parsed.count   ?? 0;
    } catch (_) {}

    return { success: true, ZipFile: zip, Count: count };  // <- renderer sẽ không còn "undefined"
  } catch (err) {
    return { success:false, message:String(err?.message||err) };
  }
});


// ======================== DRIVERS BACKUP IPC =======================

// Liệt kê driver đã cài đặt: dựa vào Win32_PnPSignedDriver (ổn định, không phụ thuộc ngôn ngữ)
// Recommended = !IsInbox (không phải driver có sẵn của Windows)
ipcMain.handle('drivers:list', async () => {
  const ps = `
$ErrorActionPreference='SilentlyContinue'

# Lấy danh sách driver từ CIM (ổn định, đa số máy đều có)
$rows = Get-CimInstance Win32_PnPSignedDriver |
  Select-Object DeviceName, FriendlyName, DriverDescription, DriverProviderName, Manufacturer,
                DeviceClass, DriverDate, DriverVersion, IsInbox, InfName, Driver, DeviceID, Signer

$out = foreach($r in $rows){
  # PublishedName (INF) ưu tiên: InfName -> Driver
  $pub  = $r.InfName
  if (-not $pub -or $pub -eq '') { $pub = $r.Driver }

  # Nếu vẫn không có INF thì bỏ qua (không hiển thị, không sao lưu)
  if (-not $pub -or $pub -eq '') { continue }

  # Tên thiết bị
  $dev = $r.DeviceName
  if (-not $dev -or $dev -eq '') { $dev = $r.FriendlyName }
  if (-not $dev -or $dev -eq '') { $dev = $r.DriverDescription }
  if (-not $dev -or $dev -eq '') { $dev = $r.DeviceClass }

  # Provider
  $prov = $r.DriverProviderName
  if (-not $prov -or $prov -eq '') { $prov = $r.Manufacturer }

  # Chuẩn hóa ngày
  $date = $null
  if ($r.DriverDate) {
    try { $date = (Get-Date $r.DriverDate).ToString('yyyy-MM-dd') } catch { $date = [string]$r.DriverDate }
  }

  # Provider có phải Microsoft không?
  $isMs = $false
  if ($prov) {
    $isMs = ($prov -match '^(?i)(Microsoft( Corporation)?|Microsoft Windows|Windows)$')
  }

  # Khuyến nghị = không Inbox & không Microsoft
  $reco = (-not [bool]$r.IsInbox) -and (-not $isMs)

  [pscustomobject]@{
    DeviceName    = [string]$dev
    PublishedName = [string]$pub
    ProviderName  = [string]$prov
    ClassName     = [string]$r.DeviceClass
    Date          = $date
    Version       = [string]$r.DriverVersion
    Inbox         = [bool]$r.IsInbox
    ProviderIsMicrosoft = [bool]$isMs
    Recommended   = [bool]$reco
    SignerName    = [string]$r.Signer
    DeviceID      = [string]$r.DeviceID
  }
}


# Sắp xếp: Khuyến nghị trước, rồi theo Class/Provider/Device
$out = $out | Sort-Object -Property @{Expression='Recommended';Descending=$true}, ClassName, ProviderName, DeviceName, PublishedName
$out | ConvertTo-Json -Depth 5 -Compress
`;
  return await runPowerShellCommand(ps);
});


ipcMain.handle('drivers:backup', async (_e, payload) => {
  try {
    const { publishedNames, outputDir } = payload || {};
    if (!outputDir || !String(outputDir).trim()) {
      return { success:false, message:'Thiếu thư mục lưu.' };
    }
    const tmp = path.join(os.tmpdir(), 'backup-drivers.ps1');
    const ps = `
param([string[]]$List,[string]$OutBase)
$ErrorActionPreference='Stop'

$ts     = Get-Date -Format 'yyyyMMdd-HHmmss'
$tmpDir = Join-Path $OutBase ("Drivers-" + $ts)   # thư mục tạm
if (-not (Test-Path -LiteralPath $tmpDir)) { New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null }

# Nếu không truyền danh sách -> export toàn bộ driver third-party (không inbox)
if (-not $List -or $List.Count -eq 0) {
  pnputil /export-driver * "$tmpDir" | Out-Null
} else {
  foreach($pn in $List){
    try { pnputil /export-driver "$pn" "$tmpDir" | Out-Null } catch {}
  }
}

# Ghi manifest nhỏ để đối chiếu
$exported = Get-ChildItem -LiteralPath $tmpDir -Recurse -Filter *.inf -ErrorAction SilentlyContinue | Select-Object -Expand FullName
[pscustomobject]@{
  Time  = (Get-Date)
  Count = ($exported | Measure-Object).Count
  Files = $exported
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $tmpDir 'drivers-export.json') -Encoding UTF8

# Đóng gói ZIP vào thư mục backup gốc
$zipPath = Join-Path $OutBase ("Drivers-$ts.zip")
if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
Compress-Archive -Path $tmpDir\\* -DestinationPath $zipPath -Force

# Dọn dẹp
Remove-Item -LiteralPath $tmpDir -Recurse -Force

# Trả kết quả
[pscustomobject]@{ ZipFile=$zipPath } | ConvertTo-Json -Compress
    `;
    fs.writeFileSync(tmp, ps, 'utf8');

    const outBase = String(outputDir || backupDir).trim();
    const argList = Array.isArray(publishedNames) ? publishedNames : [];
    const r = await runPowerShellCommand(
      `powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File "${tmp}" -List @(${argList.map(n => `"${String(n).replace(/"/g,'`"')}"`).join(',')}) -OutBase "${String(outBase).replace(/`/g,'``').replace(/"/g,'`"')}"`
    );
    if (!r.success) return r;
    const parsed = JSON.parse(r.data || '{}');
    return { success:true, ZipFile: parsed.ZipFile };
  } catch (err) {
    return { success:false, message:String(err?.message || err) };
  }
});

// ======================== BACKUP DATA (USER FILES) ========================

// 1) Trả về danh sách "gốc" cho Cột 1 (Cơ bản / Nâng cao) với path đã resolve
ipcMain.handle('backupdata:getRoots', async () => {
  const ps = `
$ErrorActionPreference='SilentlyContinue'
function P($name){ return [Environment]::GetFolderPath($name) }

$home   = [Environment]::GetFolderPath('UserProfile')
$docs   = [Environment]::GetFolderPath('MyDocuments')
$desk   = [Environment]::GetFolderPath('Desktop')
$pics   = [Environment]::GetFolderPath('MyPictures')
$music  = [Environment]::GetFolderPath('MyMusic')
$vids   = [Environment]::GetFolderPath('MyVideos')
# Downloads không có enum chính thức trên PS5 -> ghép từ home
$dl     = Join-Path $home 'Downloads'
$cont   = Join-Path $home 'Contacts'

$local  = $env:LOCALAPPDATA
$roam   = $env:APPDATA
$pf     = $env:ProgramFiles
$pf86   = [Environment]::GetFolderPath('ProgramFilesX86')

$items = @(
  # BASIC
  [pscustomobject]@{ Key='contacts';  Group='basic';   Label='Contacts';        Path=$cont;  Note=$null },
  [pscustomobject]@{ Key='desktop';   Group='basic';   Label='Desktop';         Path=$desk;  Note=$null },
  [pscustomobject]@{ Key='documents'; Group='basic';   Label='Documents';       Path=$docs;  Note=$null },
  [pscustomobject]@{ Key='downloads'; Group='basic';   Label='Downloads';       Path=$dl;    Note=$null },
  [pscustomobject]@{ Key='music';     Group='basic';   Label='Music';           Path=$music; Note=$null },
  [pscustomobject]@{ Key='pictures';  Group='basic';   Label='Pictures';        Path=$pics;  Note=$null },
  [pscustomobject]@{ Key='videos';    Group='basic';   Label='Videos';          Path=$vids;  Note=$null },
  # ADVANCED
  [pscustomobject]@{ Key='local';     Group='advanced';Label='AppData\\Local';  Path=$local; Note=$null },
  [pscustomobject]@{ Key='roaming';   Group='advanced';Label='AppData\\Roaming';Path=$roam;  Note=$null },
  [pscustomobject]@{ Key='pf';        Group='advanced';Label='Program Files';   Path=$pf;    Note=$null },
  [pscustomobject]@{ Key='pf86';      Group='advanced';Label='Program Files (x86)'; Path=$pf86; Note=$null }
)

# Chỉ trả những path tồn tại
$items = $items | Where-Object { $_.Path -and (Test-Path -LiteralPath $_.Path) }
$items | ConvertTo-Json -Depth 4 -Compress
`;
  return await runPowerShellCommand(ps);
});

// Liệt kê con trực tiếp (dir + file), có cờ HasChildren để renderer biết còn cấp dưới không
ipcMain.handle('backupdata:listChildren', async (_e, payload) => {
  try {
    const target = (payload && payload.path) ? String(payload.path) : '';
    if (!target) return { success:false, message:'Thiếu path.' };

    // Viết script tạm trước rồi gọi -File (tránh escape lỗi)
    const lsPath = path.join(os.tmpdir(), 'ls-children.ps1');
    const ps = `
param([string]$Path)
$ErrorActionPreference='SilentlyContinue'

if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { @() | ConvertTo-Json -Compress; exit }

$docs = [Environment]::GetFolderPath('MyDocuments')
$zalo = if ($docs) { Join-Path $docs 'Zalo Received Files' } else { $null }

# Lấy danh sách cấp 1, bỏ Hidden/System
$items = Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue |
  Where-Object { -not $_.Attributes.HasFlag([IO.FileAttributes]::Hidden) -and -not $_.Attributes.HasFlag([IO.FileAttributes]::System) }

# Nếu đang duyệt Documents, loại "Zalo Received Files"
if ($zalo -and ([IO.Path]::GetFullPath($Path).TrimEnd('\\') -ieq [IO.Path]::GetFullPath($docs).TrimEnd('\\'))) {
  $items = $items | Where-Object { [IO.Path]::GetFullPath($_.FullName) -ine [IO.Path]::GetFullPath($zalo) }
}

# Tạo output + cờ HasChildren cho folder
$out = foreach($i in $items){
  try {
    $isDir = [bool]$i.PSIsContainer
    $sz = if ($isDir) { $null } else { $i.Length }
    $has = $false
    if ($isDir) {
      $child = Get-ChildItem -LiteralPath $i.FullName -Force -ErrorAction SilentlyContinue |
        Where-Object { -not $_.Attributes.HasFlag([IO.FileAttributes]::Hidden) -and -not $_.Attributes.HasFlag([IO.FileAttributes]::System) } |
        Select-Object -First 1
      $has = [bool]$child
    }
    [pscustomobject]@{
      Name = $i.Name
      FullPath = $i.FullName
      Type = if ($isDir) { 'dir' } else { 'file' }
      Size = $sz
      HasChildren = $has
    }
  } catch {}
}
$out | Sort-Object -Property @{Expression='Type';Descending=$true}, Name |
  ConvertTo-Json -Depth 4 -Compress
`;
    fs.writeFileSync(lsPath, ps, 'utf8');

    const cmd = `powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File "${lsPath}" -Path "${target.replace(/`/g,'``').replace(/"/g,'`"')}"`;
    return await runPowerShellCommand(cmd);
  } catch (err) {
    return { success:false, message:String(err?.message || err) };
  }
});


// 3) Sao lưu: copy các path đã chọn vào thư mục tạm -> nén ZIP đặt ngay trong thư mục backup -> xoá tạm

// --- main.js: handler gộp 1 ZIP đặt theo tên rootName ---
ipcMain.handle('backupdata:backup', async (_e, payload) => {
  try {
    const { paths, outputDir, rootName } = payload || {};
    const root = String(rootName || 'Data').trim();

    if (!outputDir || !String(outputDir).trim())
      return { success:false, message:'Thiếu thư mục lưu.' };
    if (!Array.isArray(paths) || paths.length === 0)
      return { success:false, message:'Chưa chọn thư mục/file.' };

    // ✔ đảm bảo thư mục đích tồn tại
    try { fs.mkdirSync(outputDir, { recursive: true }); } catch {}

    const psPath     = path.join(os.tmpdir(), 'backup-data.ps1');
    const listFile   = path.join(os.tmpdir(), `backup-list-${Date.now()}.txt`);
    const resultFile = path.join(os.tmpdir(), `backup-results-${Date.now()}.json`);

    // 1) ghi danh sách file/folder cần backup (mỗi dòng một path)
    fs.writeFileSync(listFile, paths.join('\n'), 'utf8');

    // 2) PowerShell: nén thành 1 file ZIP duy nhất theo rootName, luôn tạo OutBase,
    //    và nếu stage rỗng thì tạo .keep để tránh Compress-Archive lỗi
    const ps = `
param([string]$ListFile,[string]$OutBase,[string]$RootName,[string]$ResultFile)
$ErrorActionPreference='Stop'
if ([string]::IsNullOrWhiteSpace($RootName)) { $RootName = 'Data' }
$RootName = $RootName -replace '[\\\\/:*?"<>|]', '_'

# Đảm bảo thư mục đích tồn tại
if (-not (Test-Path -LiteralPath $OutBase)) {
  New-Item -ItemType Directory -Path $OutBase -Force | Out-Null
}

# Đọc danh sách mục cần sao lưu
$items = @()
try {
  $items = Get-Content -LiteralPath $ListFile -ErrorAction Stop | Where-Object { $_ -ne '' }
} catch {
  $items = @()
}

$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$zipFile = Join-Path $OutBase ("$RootName-$ts.zip")

if ($items.Count -eq 0) {
  # Không có gì để copy -> tạo zip rỗng (.keep) cho nhất quán
  $tempDir = Join-Path $env:TEMP ("bbbackup_" + [guid]::NewGuid())
  New-Item -ItemType Directory -Path $tempDir | Out-Null
  Set-Content -LiteralPath (Join-Path $tempDir '.keep') -Value 'empty'
  if (Test-Path -LiteralPath $zipFile) { Remove-Item -LiteralPath $zipFile -Force }
  Compress-Archive -Path (Join-Path $tempDir '*') -DestinationPath $zipFile -Force
  Remove-Item -LiteralPath $tempDir -Recurse -Force

  @(@{ Name=$RootName; ZipFile=$zipFile; Error=$null }) |
    ConvertTo-Json -Compress | Out-File -LiteralPath $ResultFile -Encoding UTF8 -Force
  exit 0
}

# Có danh sách -> copy vào staging
$tempDir = Join-Path $env:TEMP ("bbbackup_" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tempDir | Out-Null

$copied = $false
foreach($p in $items){
  if (Test-Path -LiteralPath $p) {
    $leaf = Split-Path -Path $p -Leaf
    $dest = Join-Path $tempDir $leaf
    try {
      Copy-Item -LiteralPath $p -Destination $dest -Recurse -Force -ErrorAction Stop
      $copied = $true
    } catch {
      # bỏ qua mục lỗi
    }
  }
}

# Nếu không copy được gì -> vẫn nén zip rỗng
if (-not $copied) {
  Set-Content -LiteralPath (Join-Path $tempDir '.keep') -Value 'empty'
}

if (Test-Path -LiteralPath $zipFile) { Remove-Item -LiteralPath $zipFile -Force }
Compress-Archive -Path (Join-Path $tempDir '*') -DestinationPath $zipFile -Force
Remove-Item -LiteralPath $tempDir -Recurse -Force

@(@{ Name=$RootName; ZipFile=$zipFile; Error=$null }) |
  ConvertTo-Json -Depth 3 -Compress | Out-File -LiteralPath $ResultFile -Encoding UTF8 -Force
`;
    fs.writeFileSync(psPath, ps, 'utf8');

    // 3) gọi PS (có RootName)
    const q = s => `"${String(s).replace(/`/g,'``').replace(/"/g,'`"')}"`;
    const args = [
      '-NoLogo','-NonInteractive','-NoProfile','-ExecutionPolicy','Bypass',
      '-File',       q(psPath),
      '-ListFile',   q(listFile),
      '-OutBase',    q(outputDir),
      '-RootName',   q(root),
      '-ResultFile', q(resultFile)
    ];
    const cmd = `powershell ${args.join(' ')}`;
    const r = await runPowerShellCommand(cmd);
    if (!r.success) return r;

    // 4) đọc kết quả JSON; nếu rỗng -> fallback quét thư mục đích
    let results = [];
    try {
      const raw = fs.readFileSync(resultFile, 'utf8');
      if (raw && raw.trim()) results = JSON.parse(raw);
    } catch {}
    finally {
      try { fs.unlinkSync(resultFile) } catch {}
      try { fs.unlinkSync(listFile) } catch {}
    }

    if (!Array.isArray(results) || results.length === 0) {
      const now = Date.now();
      const cands = fs.readdirSync(outputDir)
        .filter(n => n.toLowerCase().endsWith('.zip') && n.startsWith(`${root}-`))
        .map(n => {
          const p = path.join(outputDir, n);
          const st = fs.statSync(p);
          return { p, m: st.mtimeMs, s: st.size };
        })
        .filter(o => (now - o.m) < 5*60*1000 && o.s > 0)
        .sort((a,b)=> b.m - a.m);
      if (cands[0]) results = [{ Name: root, ZipFile: cands[0].p, Fallback: true }];
    }

    return { success:true, results };
  } catch (err) {
    return { success:false, message:String(err?.message || err) };
  }
});



// ================== Zalo Backup IPC ==================
ipcMain.handle('zalo:backup', async (_e, payload) => {
  try {
    const outBase = String(payload?.outputDir || '').trim();
    if (!outBase) return { success:false, message:'Thiếu thư mục lưu.' };

    // Tìm Documents: ưu tiên OneDrive\Documents rồi tới Documents thường
    const home = os.homedir();
    const candidates = [
      path.join(home, 'OneDrive', 'Documents'),
      path.join(home, 'Documents')
    ];
    let docDir = candidates.find(p => fs.existsSync(p)) || path.join(home, 'Documents');

    const zaloDir = path.join(docDir, 'Zalo Received Files');
    // Nếu chưa có thì tự tạo thư mục rỗng
  if (!fs.existsSync(zaloDir)) {
  fs.mkdirSync(zaloDir, { recursive: true });
  }


    const psPath     = path.join(os.tmpdir(), 'backup-zalo.ps1');
    const resultFile = path.join(os.tmpdir(), `backup-zalo-${Date.now()}.json`);

    const ps = `
param([string]$Src,[string]$OutBase,[string]$ResultFile)
$ErrorActionPreference = 'Stop'

# 1) Bảo đảm 2 thư mục tồn tại
if (-not (Test-Path -LiteralPath $OutBase)) {
  New-Item -ItemType Directory -Path $OutBase -Force | Out-Null
}
if (-not (Test-Path -LiteralPath $Src)) {
  # nếu chưa có thư mục nguồn -> tạo rỗng để vẫn nén được
  New-Item -ItemType Directory -Path $Src -Force | Out-Null
}

# 2) Tên tệp ZIP
$ts  = Get-Date -Format 'yyyyMMdd-HHmmss'
$zip = Join-Path $OutBase ("Zalo-Received-Files-$ts.zip")

# 3) Thư mục tạm và thu thập dữ liệu
$temp = Join-Path $env:TEMP ("bb_zalo_" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $temp -Force | Out-Null

# Kiểm tra có dữ liệu không
$hasFiles = $false
try {
  $items = Get-ChildItem -LiteralPath $Src -Force -ErrorAction SilentlyContinue
  if ($items -and $items.Count -gt 0) { $hasFiles = $true }
} catch {}

if ($hasFiles) {
  Copy-Item -LiteralPath (Join-Path $Src '*') -Destination $temp -Recurse -Force -ErrorAction SilentlyContinue
} else {
  # nếu rỗng, tạo 1 file để Compress-Archive không lỗi
  Set-Content -LiteralPath (Join-Path $temp '.keep') -Value 'empty'
}

# 4) Nén
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
Compress-Archive -Path (Join-Path $temp '*') -DestinationPath $zip -Force

# 5) Dọn và trả JSON
Remove-Item -LiteralPath $temp -Recurse -Force

@(@{ Name='Zalo Received Files'; ZipFile=$zip; Error=$null }) |
  ConvertTo-Json -Compress | Out-File -LiteralPath $ResultFile -Encoding UTF8 -Force
`;
    fs.writeFileSync(psPath, ps, 'utf8');

    const q = s => `"${String(s).replace(/`/g,'``').replace(/"/g,'`"')}"`;
    const cmd = `powershell -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -File ${q(psPath)} -Src ${q(zaloDir)} -OutBase ${q(outBase)} -ResultFile ${q(resultFile)}`;

    const r = await runPowerShellCommand(cmd);
    if (!r.success) return r;

    let results = [];
    try {
      const raw = fs.readFileSync(resultFile, 'utf8');
      if (raw && raw.trim()) results = JSON.parse(raw);
    } catch {}
    finally {
      try { fs.unlinkSync(resultFile); } catch {}
    }

    // Fallback: nếu vì lý do gì chưa ghi JSON, cố gắng dò file zip mới tạo
    if (!Array.isArray(results) || results.length === 0) {
      const files = fs.readdirSync(outBase)
        .filter(n => n.toLowerCase().startsWith('zalo-received-files-') && n.toLowerCase().endsWith('.zip'))
        .map(n => ({ p: path.join(outBase, n), m: fs.statSync(path.join(outBase, n)).mtimeMs }))
        .sort((a,b) => b.m - a.m);
      if (files[0]) results = [{ Name: 'Zalo Received Files', ZipFile: files[0].p }];
    }

    return { success:true, results };
  } catch (err) {
    return { success:false, message:String(err?.message || err) };
  }
});

// ======================== REGISTRY BACKUP =========================
// Liệt kê các mục registry (phần mềm & control panel mở rộng - ASCII-safe)
ipcMain.handle('registry:list', async () => {
  try {
    const timeTag = new Date().toISOString().replace(/\D/g, '').slice(0, 14);
    const ps = String.raw`
$ErrorActionPreference = 'Stop'
# Tránh lỗi mã hóa stdout khi parse JSON
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

# Lấy các khóa con mức 1 của HKCU:\Software
$soft = @(Get-ChildItem -Path 'HKCU:\Software' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName) | Sort-Object

# Control Panel (cơ bản + nâng cao trong Control Panel)
$cp = @(
  @{ Name='Mouse';                 Path='HKEY_CURRENT_USER\Control Panel\Mouse' }
  @{ Name='Keyboard';              Path='HKEY_CURRENT_USER\Control Panel\Keyboard' }
  @{ Name='Desktop';               Path='HKEY_CURRENT_USER\Control Panel\Desktop' }
  @{ Name='Desktop\WindowMetrics'; Path='HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics' }
  @{ Name='Colors';                Path='HKEY_CURRENT_USER\Control Panel\Colors' }
  @{ Name='Cursors';               Path='HKEY_CURRENT_USER\Control Panel\Cursors' }
  @{ Name='Accessibility';         Path='HKEY_CURRENT_USER\Control Panel\Accessibility' }
  @{ Name='International';         Path='HKEY_CURRENT_USER\Control Panel\International' }
  @{ Name='Input Method';          Path='HKEY_CURRENT_USER\Control Panel\Input Method' }
  @{ Name='PowerCfg';              Path='HKEY_CURRENT_USER\Control Panel\PowerCfg' }
  @{ Name='AppEvents (Sound)';     Path='HKEY_CURRENT_USER\AppEvents' }
)

$softObjs = @()
foreach($n in $soft){
  if($n){ $softObjs += @{ Name=$n; Path=("HKEY_CURRENT_USER\Software\{0}" -f $n) } }
}

@{ Software = $softObjs; ControlPanel = $cp } | ConvertTo-Json -Depth 4 -Compress
`;
    const psFile = path.join(os.tmpdir(), `list-registry-${timeTag}.ps1`);
    // UTF-8 thường là đủ (đã tránh ký tự có dấu); nếu vẫn lỗi encoding, đổi 'utf8' -> 'utf16le'
    fs.writeFileSync(psFile, ps, 'utf8');

    const r = await runPowerShellCommand(`powershell -NoProfile -ExecutionPolicy Bypass -File "${psFile}"`);
    try { fs.unlinkSync(psFile); } catch {}

    if (!r.success) return { success:false, message:r.message || 'PowerShell error' };
    let data = {};
    try { data = JSON.parse(r.data || '{}'); } catch {}
    return { success:true, data };
  } catch (err) {
    return { success:false, message:String(err?.message || err) };
  }
});


// ================= REGISTRY BACKUP (gộp 1 ZIP, an toàn kiểu dữ liệu) =================
ipcMain.handle('registry:backup', async (_e, { keys, outputDir }) => {
  try {
    if (!outputDir) return { success:false, message:'Thiếu thư mục lưu.' };
    if (!Array.isArray(keys) || keys.length === 0)
      return { success:false, message:'Chưa chọn phần Registry nào để sao lưu.' };

    // Map nhanh các nhánh lớn
    const keyMap = {
      hkcu_software:      'HKEY_CURRENT_USER\\Software',
      hkcu_control_panel: 'HKEY_CURRENT_USER\\Control Panel',
    };

    // Chuẩn hóa về danh sách đường dẫn tuyệt đối
    const selectedPaths = [];
    for (const k of keys) {
      if (typeof k !== 'string') continue;
      if (k.startsWith('reg:')) {
        const p = k.slice(4).trim();
        if (p) selectedPaths.push(p);
      } else if (keyMap[k]) {
        selectedPaths.push(keyMap[k]);
      }
    }
    if (!selectedPaths.length) return { success:false, message:'Danh sách đường dẫn rỗng.' };

    const timeTag = new Date().toISOString().replace(/\D/g, '').slice(0,14);
    const tempDir = path.join(os.tmpdir(), `BBBackup-Reg-${timeTag}`);
    const zipPath = path.join(outputDir, `Registry-${timeTag}.zip`);

    // 1) Export từng nhánh -> .reg trong thư mục tạm (chạy trực tiếp PS script, không truyền tham số phức tạp)
    const listLiteral = selectedPaths.map(p => `'${p.replace(/'/g, "''")}'`).join(', ');
    const psExport = String.raw`
$ErrorActionPreference='Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$Temp  = '${tempDir.replace(/\\/g,'/')}'
$Paths = @(${listLiteral})
New-Item -ItemType Directory -Path $Temp -Force | Out-Null

function SafeName([string]$s){
  $n = $s -replace '^HKEY_CURRENT_USER\\','HKCU\' -replace '[^A-Za-z0-9._-]+','-' -replace '-+','-'
  if([string]::IsNullOrWhiteSpace($n)){ $n = 'item' }
  return $n.Trim('-')
}

$items = @()
foreach($p in $Paths){
  try{
    $leaf = ($p -split '\\')[-1]; if([string]::IsNullOrWhiteSpace($leaf)){ $leaf = $p }
    $name = SafeName($leaf)
    $reg  = Join-Path $Temp ($name + '.reg')
    $null = & reg.exe export "$p" "$reg" /y
    if (Test-Path -LiteralPath $reg) { $items += @{ Path=$p; Reg=$reg; Ok=$true } 
      } else { $items += @{ Path=$p; Error='Export failed'; Ok=$false } }
  } catch { $items += @{ Path=$p; Error=$_.Exception.Message; Ok=$false } }
}
$items | ConvertTo-Json -Compress
`;
    const r1 = await runPowerShellCommand(psExport);
    if (!r1.success) {
      try { fs.rmSync(tempDir, { recursive:true, force:true }); } catch {}
      return { success:false, message:r1.message || 'Export thất bại' };
    }

    let items = [];
    try {
      // r1.data phải là JSON array; nếu không, ép về []
      const parsed = JSON.parse(r1.data || '[]');
      items = Array.isArray(parsed) ? parsed : [];
    } catch { items = []; }

    const okCount = items.filter(it => it && it.Ok).length;
    if (okCount === 0) {
      try { fs.rmSync(tempDir, { recursive:true, force:true }); } catch {}
      return { success:false, message:'Không có khóa nào export được.' };
    }

    // 2) Nén toàn bộ .reg ở thư mục tạm -> 1 ZIP
    const psZip = String.raw`
param([string]$Src,[string]$Zip)
$ErrorActionPreference='Stop'
if (Test-Path -LiteralPath $Zip) { Remove-Item -LiteralPath $Zip -Force -ErrorAction SilentlyContinue }
Compress-Archive -Path (Join-Path $Src '*.reg') -DestinationPath $Zip -Force
'OK'
`;
    const tmpZipPs = path.join(os.tmpdir(), `zip-reg-${timeTag}.ps1`);
    fs.writeFileSync(tmpZipPs, psZip, 'utf8');
    const r2 = await runPowerShellCommand(
      `powershell -NoProfile -ExecutionPolicy Bypass -File "${tmpZipPs}" -Src "${tempDir}" -Zip "${zipPath}"`
    );
    try { fs.unlinkSync(tmpZipPs); } catch {}

    // 3) Dọn rác
    try { fs.rmSync(tempDir, { recursive:true, force:true }); } catch {}

    if (!r2.success) return { success:false, message:r2.message || 'Nén ZIP thất bại' };
if (!fs.existsSync(zipPath)) {
  return { success:false, message:'Không tìm thấy file ZIP sau khi nén.' };
}
    // Trả về theo format cũ để renderer không phải sửa nhiều
    return {
  success: true,
  ZipFile: zipPath,   // giữ tên cũ (viết hoa)
  zip: zipPath,       // thêm tên phổ biến (viết thường) để renderer cũ không lỗi
  items
};
  } catch (err) {
    return { success:false, message:String(err?.message || err) };
  }
});

// ======================== RESTORE DATA =========================
// ===== LOCAL known folders (ignore OneDrive) =====
function userProfileDir() {
  return process.env.USERPROFILE || path.join('C:\\Users', require('os').userInfo().username);
}
function pathDesktopLocal()    { return path.join(userProfileDir(), 'Desktop'); }
function pathDocumentsLocal()  { return path.join(userProfileDir(), 'Documents'); }
function pathLocalAppData()    { return process.env.LOCALAPPDATA || path.join(userProfileDir(), 'AppData', 'Local'); }
function pathRoamingAppData()  { return process.env.APPDATA      || path.join(userProfileDir(), 'AppData', 'Roaming'); }
function pathProgramFiles()    { return process.env['ProgramFiles']      || 'C:\\Program Files'; }
function pathProgramFilesX86() { return process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)'; }


// ===== Build catalog from backup folder =====
function buildRestoreCatalog(baseDir){
  const items = [];
  const list = fs.readdirSync(baseDir, { withFileTypes:true });

  for (const ent of list) {
    if (!ent.isFile()) continue;
    const p = path.join(baseDir, ent.name);
    const name = ent.name;               // giữ chữ hoa/thường để hiển thị
    const lower = name.toLowerCase();    // để so pattern

    // 1) Registry
    if (/^registry[-_].*\.zip$/.test(lower)) {
      items.push({
        id: 'registry:'+name,
        label: 'Registry Keys',
        source: p, sourceName: name,
        targetHint: 'Nhập lại các khóa Registry đã sao lưu (Cần quyền Admin)',
        kind: 'registry', restorable: true
      });
      continue;
    }

    // 2) Wi-Fi
    if (/^wifi[-_].*\.zip$/.test(lower)) {
      items.push({
        id: 'wifi:'+name,
        label: 'Wi-Fi Profiles',
        source: p, sourceName: name,
        targetHint: 'Nhập lại cấu hình mạng (netsh)',
        kind: 'wifi', restorable: true
      });
      continue;
    }

    // 3) Zalo
    if (/^(zalo[-_]|zalo-received-files).+\.zip$/.test(lower)) {
      const target = path.join(pathDocumentsLocal(), 'Zalo Received Files');
      items.push({
        id: 'zalo:'+name,
        label: 'Zalo Received Files',
        source: p, sourceName: name,
        targetHint: target,
        kind: 'zalo', restorable: true
      });
      continue;
    }

    // 4) Desktop
    if (/^desktop[-_].*\.zip$/.test(lower)) {
      items.push({
        id: 'desktop:'+name,
        label: 'Desktop (merge về màn hình Desktop)',
        source: p, sourceName: name,
        targetHint: pathDesktopLocal(),
        kind: 'desktop', restorable: true
      });
      continue;
    }

    // 5) AppData_Local
    if (/^appdata[_ -]?local[-_].*\.zip$/.test(lower)) {
      items.push({
        id: 'appdata_local:'+name,
        label: 'AppData\\Local',
        source: p, sourceName: name,
        targetHint: pathLocalAppData(),
        kind: 'appdata_local', restorable: true
      });
      continue;
    }

    // 6) AppData_Roaming
    if (/^appdata[_ -]?roaming[-_].*\.zip$/.test(lower)) {
      items.push({
        id: 'appdata_roaming:'+name,
        label: 'AppData\\Roaming',
        source: p, sourceName: name,
        targetHint: pathRoamingAppData(),
        kind: 'appdata_roaming', restorable: true
      });
      continue;
    }

    // 7) Program Files (x86)
    if (/^program files \(x86\)[-_].*\.zip$/.test(lower)) {
      items.push({
        id: 'programfilesx86:'+name,
        label: 'Program Files (x86)',
        source: p, sourceName: name,
        targetHint: pathProgramFilesX86(),
        kind: 'programfilesx86', restorable: true
      });
      continue;
    }

    // 8) Program Files
    if (/^program files[-_].*\.zip$/.test(lower)) {
      items.push({
        id: 'programfiles:'+name,
        label: 'Program Files',
        source: p, sourceName: name,
        targetHint: pathProgramFiles(),
        kind: 'programfiles', restorable: true
      });
      continue;
    }
  }
  return items;
}

// ===== IPC: list =====
ipcMain.handle('restore:list', async (_e, { baseDir }) => {
  try {
    if (!baseDir || !fs.existsSync(baseDir)) return { success:false, message:'Thư mục backup không tồn tại.' };
    const items = buildRestoreCatalog(baseDir);
    return { success:true, items };
  } catch (err) {
    return { success:false, message: err.message };
  }
});

// Liệt kê các file .REG trong 1 file ZIP (không giải nén)
ipcMain.handle('registry:zip-entries', async (_e, { zipPath }) => {
  try {
    if (!zipPath || !fs.existsSync(zipPath)) {
      return { success:false, message:'ZIP không tồn tại.' };
    }
    const timeTag = new Date().toISOString().replace(/\D/g, '').slice(0,14);
    const ps = String.raw`
param([string]$Zip)
try {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $z = [System.IO.Compression.ZipFile]::OpenRead($Zip)
  $list = @()
  foreach($e in $z.Entries){
    if ($e.Name -match '\.reg$'){
      $list += @{ Name = $e.FullName; Size = $e.Length }
    }
  }
  $z.Dispose()
  $list | ConvertTo-Json -Compress
} catch { '[]' }
`;
    const psFile = path.join(os.tmpdir(), `ls-reg-in-zip-${timeTag}.ps1`);
    fs.writeFileSync(psFile, ps, 'utf8');
    const r = await runPowerShellCommand(`powershell -NoProfile -ExecutionPolicy Bypass -File "${psFile}" -Zip "${zipPath}"`);
    try { fs.unlinkSync(psFile); } catch {}
    let entries = [];
    try { entries = JSON.parse(r.data || '[]'); } catch {}
    return { success:true, entries };
  } catch (err) {
    return { success:false, message:String(err?.message || err) };
  }
});

// ===== IPC: run =====
ipcMain.handle('restore:run', async (_e, { baseDir, ids, regSelections }) => {
  if (!Array.isArray(ids) || !ids.length) return { success: false, message: 'Chưa chọn gói khôi phục.' };
  const all = buildRestoreCatalog(baseDir);
  const chosen = all.filter(x => ids.includes(x.id) && x.restorable);
  const results = [];

  for (const it of chosen) {
    try {
      // --- Zalo: dùng Documents (LOCAL) ---
      if (it.kind === 'zalo') {
        const target = path.join(pathDocumentsLocal(), 'Zalo Received Files');
        const timeTag = new Date().toISOString().replace(/\D/g, '').slice(0, 14);
        const temp = path.join(os.tmpdir(), `BBRestore-Zalo-${timeTag}`);
        if (!fs.existsSync(temp)) fs.mkdirSync(temp, { recursive: true });

        // KHÔNG có backtick PowerShell bên trong
        const ps = String.raw`
param([string]$Zip,[string]$Temp,[string]$Target,[string]$ProcsCsv)
try {
  if ($ProcsCsv) {
    $names = $ProcsCsv -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    foreach ($n in $names) { Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 300
  }
  if (!(Test-Path -LiteralPath $Temp)) { New-Item -ItemType Directory -Path $Temp | Out-Null }
  Expand-Archive -Path $Zip -DestinationPath $Temp -Force
  if (!(Test-Path -LiteralPath $Target)) { New-Item -ItemType Directory -Path $Target | Out-Null }
  $log = Join-Path $env:TEMP ("BBRestore-" + (Get-Date -Format 'yyyyMMddHHmmss') + ".log")
  $xd  = @("Cache","*Cache*","Code Cache","GPUCache","Temp","tmp","htmlcache","Service Worker","Crashpad","ShaderCache","Media Cache")
  $xf  = @("*.lock","LOCK","*.-journal","*journal*","desktop.ini")
  robocopy "$Temp" "$Target" /E /R:0 /W:0 /XO /XC /XN /NFL /NDL /NJH /NJS /NP /LOG:"$log" /XD $xd /XF $xf | Out-Null
  $rc = $LASTEXITCODE
  $nl = [Environment]::NewLine
  "RC:$rc$nlLOG:$log"
} catch { Write-Output $_.Exception.Message; exit 1 }
`;
        const psFile = path.join(os.tmpdir(), `restore-zalo-${timeTag}.ps1`);
        fs.writeFileSync(psFile, ps, 'utf8');
        const r = await runPowerShellCommand(
          `powershell -NoProfile -ExecutionPolicy Bypass -File "${psFile}" -Zip "${it.source}" -Temp "${temp}" -Target "${target}" -ProcsCsv "Zalo,ZaloPC"`
        );
        try { fs.rmSync(temp, { recursive: true, force: true }); } catch (e) {}
        const rc = (r.data || '').match(/RC:(\d+)/)?.[1];
        const ok = r.success && rc && Number(rc) < 8;
        results.push({
          id: it.id,
          label: it.label,
          success: ok,
          message: rc ? `Robocopy RC=${rc}` : (r.data || ''),
          target
        });
      }

      // --- Desktop: dùng LOCAL Desktop ---
      else if (it.kind === 'desktop') {
        const target = pathDesktopLocal();
        const timeTag = new Date().toISOString().replace(/\D/g, '').slice(0, 14);
        const temp = path.join(os.tmpdir(), `BBRestore-Desktop-${timeTag}`);
        if (!fs.existsSync(temp)) fs.mkdirSync(temp, { recursive: true });

        const ps = String.raw`
param([string]$Zip,[string]$Temp,[string]$Target,[string]$ProcsCsv)
try {
  if ($ProcsCsv) {
    $names = $ProcsCsv -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    foreach ($n in $names) { Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 300
  }
  if (!(Test-Path -LiteralPath $Temp)) { New-Item -ItemType Directory -Path $Temp | Out-Null }
  Expand-Archive -Path $Zip -DestinationPath $Temp -Force
  if (!(Test-Path -LiteralPath $Target)) { New-Item -ItemType Directory -Path $Target | Out-Null }
  $log = Join-Path $env:TEMP ("BBRestore-" + (Get-Date -Format 'yyyyMMddHHmmss') + ".log")
  $xd  = @("Cache","*Cache*","Code Cache","GPUCache","Temp","tmp","htmlcache","Service Worker","Crashpad","ShaderCache","Media Cache")
  $xf  = @("*.lock","LOCK","*.-journal","*journal*","desktop.ini")
  robocopy "$Temp" "$Target" /E /R:0 /W:0 /XO /XC /XN /NFL /NDL /NJH /NJS /NP /LOG:"$log" /XD $xd /XF $xf | Out-Null
  $rc = $LASTEXITCODE
  $nl = [Environment]::NewLine
  "RC:$rc$nlLOG:$log"
} catch { Write-Output $_.Exception.Message; exit 1 }
`;
        const psFile = path.join(os.tmpdir(), `restore-desktop-${timeTag}.ps1`);
        fs.writeFileSync(psFile, ps, 'utf8');
        const r = await runPowerShellCommand(
          `powershell -NoProfile -ExecutionPolicy Bypass -File "${psFile}" -Zip "${it.source}" -Temp "${temp}" -Target "${target}" -ProcsCsv ""`
        );
        try { fs.rmSync(temp, { recursive: true, force: true }); } catch (e) {}
        const rc = (r.data || '').match(/RC:(\d+)/)?.[1];
        const ok = r.success && rc && Number(rc) < 8;
        results.push({ id: it.id, label: it.label, success: ok, message: rc ? `Robocopy RC=${rc}` : (r.data || ''), target });
      }

// --- AppData\Local --- (AUTO close processes + detailed log)
else if (it.kind === 'appdata_local') {
  const target = pathLocalAppData();
  const timeTag = new Date().toISOString().replace(/\D/g, '').slice(0, 14);
  const temp = path.join(os.tmpdir(), `BBRestore-AppLocal-${timeTag}`);
  if (!fs.existsSync(temp)) fs.mkdirSync(temp, { recursive: true });

  const ps = String.raw`
param([string]$Zip,[string]$Temp,[string]$Target)
try {
  function Norm([string]$s){ if([string]::IsNullOrEmpty($s)){return ""} ($s -replace '[^A-Za-z0-9]','').ToLower() }
  function AutoClose([string]$Target,[string]$Temp){
    $closed=@()
    $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $allNames = $procs | ForEach-Object { $_.Name } | Sort-Object -Unique
    $cand = @{}

    if($Target){
      $t = ($Target.TrimEnd('\')+'\*')
      foreach($p in $procs){ if($p.ExecutablePath -like $t){ $cand[(Norm $p.Name)] = $p.Name } }
    }
    if(Test-Path -LiteralPath $Temp){
      $dirs = Get-ChildItem -LiteralPath $Temp -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
      foreach($d in $dirs){
        $nd = Norm $d
        foreach($n in $allNames){
          $nn = Norm $n
          if(($nn -like "*$nd*") -or ($nd -like "*$nn*")){ $cand[$nn] = $n }
        }
      }
    }
    $exclude = @('explorer','dwm','csrss','wininit','winlogon','services','lsass','svchost','system','smss','conhost','fontdrvhost','idle')
    $final = $cand.Values | Sort-Object -Unique | Where-Object { $exclude -notcontains $_ }
    foreach($f in $final){ try { Get-Process -Name $f -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue; $closed += $f } catch {} }
    Start-Sleep -Milliseconds 300
    return $closed
  }

  if (!(Test-Path -LiteralPath $Temp)) { New-Item -ItemType Directory -Path $Temp | Out-Null }
  Expand-Archive -Path $Zip -DestinationPath $Temp -Force
  if (!(Test-Path -LiteralPath $Target)) { New-Item -ItemType Directory -Path $Target | Out-Null }

  $stopped = AutoClose -Target $Target -Temp $Temp

  $log = Join-Path $env:TEMP ("BBRestore-" + (Get-Date -Format 'yyyyMMddHHmmss') + ".log")
  $xd  = @("Cache","*Cache*","Code Cache","GPUCache","Temp","tmp","htmlcache","Service Worker","Crashpad","ShaderCache","Media Cache")
  $xf  = @("*.lock","LOCK","*.-journal","*journal*","desktop.ini")
  robocopy "$Temp" "$Target" /E /R:0 /W:0 /XO /XC /XN /NJH /NP /TS /FP /LOG:"$log" /XD $xd /XF $xf | Out-Null
  $rc = $LASTEXITCODE

  $errLines = @()
  if (Test-Path -LiteralPath $log) {
    $errLines = (Select-String -Path $log -Pattern 'ERROR\s+\d+' -AllMatches | Select-Object -ExpandProperty Line | Select-Object -First 30)
  }

  [pscustomobject]@{ RC=$rc; Log=$log; Errors=$errLines; Stopped=$stopped } | ConvertTo-Json -Compress
} catch {
  [pscustomobject]@{ RC=999; Log=$null; Errors=@("$_"); Stopped=@() } | ConvertTo-Json -Compress
  exit 1
}
`;
  const psFile = path.join(os.tmpdir(), `restore-applocal-${timeTag}.ps1`);
  fs.writeFileSync(psFile, ps, 'utf8');

  const r = await runPowerShellCommand(
    `powershell -NoProfile -ExecutionPolicy Bypass -File "${psFile}" -Zip "${it.source}" -Temp "${temp}" -Target "${target}"`
  );
  try { fs.rmSync(temp, { recursive: true, force: true }); } catch {}

  let rc = 999, errs = [], logPath = '', stopped = [];
  try {
    const j = JSON.parse(r.data || '{}');
    rc = Number(j.RC);
    errs = Array.isArray(j.Errors) ? j.Errors : [];
    logPath = j.Log || '';
    stopped = Array.isArray(j.Stopped) ? j.Stopped : [];
  } catch {}

  const ok = r.success && rc < 8;
  const msg = ok
    ? `RC=${rc}${stopped.length ? ` | Đã đóng: ${stopped.join(', ')}` : ''}${logPath ? ` | Log: ${logPath}` : ''}`
    : (errs.length ? errs.join('\n') : 'Khôi phục AppData\\Local lỗi');

  results.push({ id: it.id, label: it.label, success: ok, message: msg, target });
}

// --- AppData\Roaming --- (AUTO close processes + detailed log)
else if (it.kind === 'appdata_roaming') {
  const target = pathRoamingAppData();
  const timeTag = new Date().toISOString().replace(/\D/g, '').slice(0, 14);
  const temp = path.join(os.tmpdir(), `BBRestore-AppRoaming-${timeTag}`);
  if (!fs.existsSync(temp)) fs.mkdirSync(temp, { recursive: true });

  const ps = String.raw`
param([string]$Zip,[string]$Temp,[string]$Target)
try {
  function Norm([string]$s){ if([string]::IsNullOrEmpty($s)){return ""} ($s -replace '[^A-Za-z0-9]','').ToLower() }
  function AutoClose([string]$Target,[string]$Temp){
    $closed=@()
    $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $allNames = $procs | ForEach-Object { $_.Name } | Sort-Object -Unique
    $cand = @{}

    if($Target){
      $t = ($Target.TrimEnd('\')+'\*')
      foreach($p in $procs){ if($p.ExecutablePath -like $t){ $cand[(Norm $p.Name)] = $p.Name } }
    }
    if(Test-Path -LiteralPath $Temp){
      $dirs = Get-ChildItem -LiteralPath $Temp -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
      foreach($d in $dirs){
        $nd = Norm $d
        foreach($n in $allNames){
          $nn = Norm $n
          if(($nn -like "*$nd*") -or ($nd -like "*$nn*")){ $cand[$nn] = $n }
        }
      }
    }
    $exclude = @('explorer','dwm','csrss','wininit','winlogon','services','lsass','svchost','system','smss','conhost','fontdrvhost','idle')
    $final = $cand.Values | Sort-Object -Unique | Where-Object { $exclude -notcontains $_ }
    foreach($f in $final){ try { Get-Process -Name $f -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue; $closed += $f } catch {} }
    Start-Sleep -Milliseconds 300
    return $closed
  }

  if (!(Test-Path -LiteralPath $Temp)) { New-Item -ItemType Directory -Path $Temp | Out-Null }
  Expand-Archive -Path $Zip -DestinationPath $Temp -Force
  if (!(Test-Path -LiteralPath $Target)) { New-Item -ItemType Directory -Path $Target | Out-Null }

  $stopped = AutoClose -Target $Target -Temp $Temp

  $log = Join-Path $env:TEMP ("BBRestore-" + (Get-Date -Format 'yyyyMMddHHmmss') + ".log")
  $xd  = @("Cache","*Cache*","Code Cache","GPUCache","Temp","tmp","htmlcache","Service Worker","Crashpad","ShaderCache","Media Cache")
  $xf  = @("*.lock","LOCK","*.-journal","*journal*","desktop.ini")
  robocopy "$Temp" "$Target" /E /R:0 /W:0 /XO /XC /XN /NJH /NP /TS /FP /LOG:"$log" /XD $xd /XF $xf | Out-Null
  $rc = $LASTEXITCODE

  $errLines = @()
  if (Test-Path -LiteralPath $log) {
    $errLines = (Select-String -Path $log -Pattern 'ERROR\s+\d+' -AllMatches | Select-Object -ExpandProperty Line | Select-Object -First 30)
  }

  [pscustomobject]@{ RC=$rc; Log=$log; Errors=$errLines; Stopped=$stopped } | ConvertTo-Json -Compress
} catch {
  [pscustomobject]@{ RC=999; Log=$null; Errors=@("$_"); Stopped=@() } | ConvertTo-Json -Compress
  exit 1
}
`;
  const psFile = path.join(os.tmpdir(), `restore-approaming-${timeTag}.ps1`);
  fs.writeFileSync(psFile, ps, 'utf8');

  const r = await runPowerShellCommand(
    `powershell -NoProfile -ExecutionPolicy Bypass -File "${psFile}" -Zip "${it.source}" -Temp "${temp}" -Target "${target}"`
  );
  try { fs.rmSync(temp, { recursive: true, force: true }); } catch {}

  let rc = 999, errs = [], logPath = '', stopped = [];
  try {
    const j = JSON.parse(r.data || '{}');
    rc = Number(j.RC);
    errs = Array.isArray(j.Errors) ? j.Errors : [];
    logPath = j.Log || '';
    stopped = Array.isArray(j.Stopped) ? j.Stopped : [];
  } catch {}

  const ok = r.success && rc < 8;
  const msg = ok
    ? `RC=${rc}${stopped.length ? ` | Đã đóng: ${stopped.join(', ')}` : ''}${logPath ? ` | Log: ${logPath}` : ''}`
    : (errs.length ? errs.join('\n') : 'Khôi phục AppData\\Roaming lỗi');

  results.push({ id: it.id, label: it.label, success: ok, message: msg, target });
}

// --- Program Files (x86) — cần admin + auto-close + log chi tiết ---
else if (it.kind === 'programfilesx86') {
  const target = pathProgramFilesX86();
  const timeTag = new Date().toISOString().replace(/\D/g, '').slice(0, 14);
  const temp = path.join(os.tmpdir(), `BBRestore-PFx86-${timeTag}`);
  if (!fs.existsSync(temp)) fs.mkdirSync(temp, { recursive: true });

  const ps = String.raw`
param([string]$Zip,[string]$Temp,[string]$Target)
try {
  # 0) Yêu cầu quyền admin
  $wi=[Security.Principal.WindowsIdentity]::GetCurrent()
  $wp=New-Object Security.Principal.WindowsPrincipal($wi)
  if(-not $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ 
    [pscustomobject]@{ RC=900; Log=$null; Errors=@('NEED_ADMIN'); Stopped=@() } | ConvertTo-Json -Compress
    exit 2 
  }

  function AutoCloseRoots([string]$Target,[string]$Temp){
    $closed=@()
    $roots = Get-ChildItem -LiteralPath $Temp -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    if(-not $roots){ return @() }
    $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    foreach($r in $roots){
      $pat = (Join-Path $Target $r); $pat = ($pat.TrimEnd('\') + '\*')
      foreach($p in $procs){
        if($p.ExecutablePath -and ($p.ExecutablePath -like $pat)){
          try { Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue; $closed += $p.Name } catch {}
        }
      }
    }
    Start-Sleep -Milliseconds 300
    $closed | Sort-Object -Unique
  }

  if (!(Test-Path -LiteralPath $Temp)) { New-Item -ItemType Directory -Path $Temp | Out-Null }
  Expand-Archive -Path $Zip -DestinationPath $Temp -Force
  if (!(Test-Path -LiteralPath $Target)) { New-Item -ItemType Directory -Path $Target | Out-Null }

  $stopped = AutoCloseRoots -Target $Target -Temp $Temp

  $log = Join-Path $env:TEMP ("BBRestore-" + (Get-Date -Format 'yyyyMMddHHmmss') + ".log")
  robocopy "$Temp" "$Target" /E /R:0 /W:0 /XO /XC /XN /NJH /NP /TS /FP /LOG:"$log" | Out-Null
  $rc = $LASTEXITCODE
  $errLines = @()
  if (Test-Path -LiteralPath $log) {
    $errLines = (Select-String -Path $log -Pattern 'ERROR\s+\d+' -AllMatches | Select-Object -ExpandProperty Line | Select-Object -First 30)
  }
  [pscustomobject]@{ RC=$rc; Log=$log; Errors=$errLines; Stopped=$stopped } | ConvertTo-Json -Compress
} catch {
  [pscustomobject]@{ RC=999; Log=$null; Errors=@("$_"); Stopped=@() } | ConvertTo-Json -Compress
  exit 1
}
`;
  const psFile = path.join(os.tmpdir(), `restore-pfx86-${timeTag}.ps1`);
  fs.writeFileSync(psFile, ps, 'utf8');
  const r = await runPowerShellCommand(
    `powershell -NoProfile -ExecutionPolicy Bypass -File "${psFile}" -Zip "${it.source}" -Temp "${temp}" -Target "${target}"`
  );
  try { fs.rmSync(temp, { recursive: true, force: true }); } catch (e) {}

  let rc = 999, errs = [], logPath = '', stopped = [];
  try {
    const j = JSON.parse(r.data || '{}');
    rc = Number(j.RC); errs = Array.isArray(j.Errors) ? j.Errors : [];
    logPath = j.Log || ''; stopped = Array.isArray(j.Stopped) ? j.Stopped : [];
  } catch {}

  if (errs.includes('NEED_ADMIN')) {
    results.push({ id: it.id, label: it.label, success: false, message: 'Yêu cầu chạy ứng dụng bằng quyền Administrator.' });
  } else {
    const ok = r.success && rc < 8;
    const msg = ok
      ? `RC=${rc}${stopped.length ? ` | Đã đóng: ${stopped.join(', ')}` : ''}${logPath ? ` | Log: ${logPath}` : ''}`
      : (errs.length ? errs.join('\n') : (r.data || 'Khôi phục Program Files (x86) lỗi'));
    results.push({ id: it.id, label: it.label, success: ok, target, message: msg });
  }
}

// --- Program Files — cần admin + auto-close + log chi tiết ---
else if (it.kind === 'programfiles') {
  const target = pathProgramFiles();
  const timeTag = new Date().toISOString().replace(/\D/g, '').slice(0, 14);
  const temp = path.join(os.tmpdir(), `BBRestore-PF-${timeTag}`);
  if (!fs.existsSync(temp)) fs.mkdirSync(temp, { recursive: true });

  const ps = String.raw`
param([string]$Zip,[string]$Temp,[string]$Target)
try {
  # 0) Yêu cầu quyền admin
  $wi=[Security.Principal.WindowsIdentity]::GetCurrent()
  $wp=New-Object Security.Principal.WindowsPrincipal($wi)
  if(-not $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ 
    [pscustomobject]@{ RC=900; Log=$null; Errors=@('NEED_ADMIN'); Stopped=@() } | ConvertTo-Json -Compress
    exit 2 
  }

  function AutoCloseRoots([string]$Target,[string]$Temp){
    $closed=@()
    $roots = Get-ChildItem -LiteralPath $Temp -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    if(-not $roots){ return @() }
    $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    foreach($r in $roots){
      $pat = (Join-Path $Target $r); $pat = ($pat.TrimEnd('\') + '\*')
      foreach($p in $procs){
        if($p.ExecutablePath -and ($p.ExecutablePath -like $pat)){
          try { Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue; $closed += $p.Name } catch {}
        }
      }
    }
    Start-Sleep -Milliseconds 300
    $closed | Sort-Object -Unique
  }

  if (!(Test-Path -LiteralPath $Temp)) { New-Item -ItemType Directory -Path $Temp | Out-Null }
  Expand-Archive -Path $Zip -DestinationPath $Temp -Force
  if (!(Test-Path -LiteralPath $Target)) { New-Item -ItemType Directory -Path $Target | Out-Null }

  $stopped = AutoCloseRoots -Target $Target -Temp $Temp

  $log = Join-Path $env:TEMP ("BBRestore-" + (Get-Date -Format 'yyyyMMddHHmmss') + ".log")
  robocopy "$Temp" "$Target" /E /R:0 /W:0 /XO /XC /XN /NJH /NP /TS /FP /LOG:"$log" | Out-Null
  $rc = $LASTEXITCODE
  $errLines = @()
  if (Test-Path -LiteralPath $log) {
    $errLines = (Select-String -Path $log -Pattern 'ERROR\s+\d+' -AllMatches | Select-Object -ExpandProperty Line | Select-Object -First 30)
  }
  [pscustomobject]@{ RC=$rc; Log=$log; Errors=$errLines; Stopped=$stopped } | ConvertTo-Json -Compress
} catch {
  [pscustomobject]@{ RC=999; Log=$null; Errors=@("$_"); Stopped=@() } | ConvertTo-Json -Compress
  exit 1
}
`;
  const psFile = path.join(os.tmpdir(), `restore-pf-${timeTag}.ps1`);
  fs.writeFileSync(psFile, ps, 'utf8');
  const r = await runPowerShellCommand(
    `powershell -NoProfile -ExecutionPolicy Bypass -File "${psFile}" -Zip "${it.source}" -Temp "${temp}" -Target "${target}"`
  );
  try { fs.rmSync(temp, { recursive: true, force: true }); } catch (e) {}

  let rc = 999, errs = [], logPath = '', stopped = [];
  try {
    const j = JSON.parse(r.data || '{}');
    rc = Number(j.RC); errs = Array.isArray(j.Errors) ? j.Errors : [];
    logPath = j.Log || ''; stopped = Array.isArray(j.Stopped) ? j.Stopped : [];
  } catch {}

  if (errs.includes('NEED_ADMIN')) {
    results.push({ id: it.id, label: it.label, success: false, message: 'Yêu cầu chạy ứng dụng bằng quyền Administrator.' });
  } else {
    const ok = r.success && rc < 8;
    const msg = ok
      ? `RC=${rc}${stopped.length ? ` | Đã đóng: ${stopped.join(', ')}` : ''}${logPath ? ` | Log: ${logPath}` : ''}`
      : (errs.length ? errs.join('\n') : (r.data || 'Khôi phục Program Files lỗi'));
    results.push({ id: it.id, label: it.label, success: ok, target, message: msg });
  }
}


      // --- Wi-Fi ---
      else if (it.kind === 'wifi') {
        const timeTag = new Date().toISOString().replace(/\D/g, '').slice(0, 14);
        const temp = path.join(os.tmpdir(), `BBRestore-WiFi-${timeTag}`);
        if (!fs.existsSync(temp)) fs.mkdirSync(temp, { recursive: true });
        const ps = `
param([string]$Zip,[string]$Temp)
try {
  Expand-Archive -Path $Zip -DestinationPath $Temp -Force
  $xmls = Get-ChildItem -LiteralPath $Temp -Recurse -Filter *.xml -ErrorAction SilentlyContinue
  foreach($x in $xmls){ netsh wlan add profile filename="$($x.FullName)" user=all | Out-Null }
  'OK'
} catch { Write-Output $_.Exception.Message; exit 1 }`;
        const psFile = path.join(os.tmpdir(), `restore-wifi-${timeTag}.ps1`);
        fs.writeFileSync(psFile, ps, 'utf8');
        const r = await runPowerShellCommand(
          `powershell -NoProfile -ExecutionPolicy Bypass -File "${psFile}" -Zip "${it.source}" -Temp "${temp}"`
        );
        try { fs.rmSync(temp, { recursive: true, force: true }); } catch (e) {}
        results.push({ id: it.id, label: it.label, success: r.success, message: r.success ? '' : 'Khôi phục Wi-Fi lỗi' });
      }

// --- Registry: chọn .REG trong ZIP & báo cáo chi tiết (dùng sysnative\reg.exe, không Expand-Archive)
else if (it.kind === 'registry') {
  const timeTag = new Date().toISOString().replace(/\D/g, '').slice(0, 14);
  const temp = path.join(os.tmpdir(), `BBRestore-Registry-${timeTag}`);
  if (!fs.existsSync(temp)) fs.mkdirSync(temp, { recursive: true });

  if (!it.source || !fs.existsSync(it.source)) {
    results.push({ id: it.id, label: it.label, kind:'registry', success:false, message:'Không tìm thấy file ZIP.' });
    continue;
  }

  // Danh sách .reg user đã chọn (từ renderer)
  const allowList = Array.isArray(regSelections?.[it.id]) ? regSelections[it.id] : [];
  let allowFile = '';
  if (allowList.length) {
    allowFile = path.join(os.tmpdir(), `allow-reg-${timeTag}.json`);
    fs.writeFileSync(allowFile, JSON.stringify(allowList), 'utf8');
  }

const ps = String.raw`
param([string]$Zip,[string]$Temp,[string]$AllowFile)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

# 1) Bắt buộc chạy Admin
$wi  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$wp  = New-Object Security.Principal.WindowsPrincipal($wi)
if(-not $wp.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)){
  Write-Output '__NEED_ADMIN__'; exit 2
}

# 2) Mở ZIP bằng .NET (dùng biến $zipObj để tránh đụng tham số $Zip)
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zipObj = [System.IO.Compression.ZipFile]::OpenRead($Zip)

# Lấy tất cả entry *.reg
$entries = @()
foreach($e in $zipObj.Entries){
  if ($e.FullName -match '\.reg$'){ $entries += $e }
}

# 3) Lọc theo danh sách user chọn (nếu có)
if ($AllowFile -and (Test-Path -LiteralPath $AllowFile)) {
  try { $allow = Get-Content -Raw -LiteralPath $AllowFile | ConvertFrom-Json } catch { $allow = $null }
  if ($allow) {
    $names = @(); foreach($a in $allow){ if($a){ $names += [System.IO.Path]::GetFileName("$a") } }
    if ($names.Count -gt 0) {
      $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
      foreach($n in $names){ [void]$set.Add($n) }
      $entries = $entries | Where-Object { $set.Contains($_.Name) }
    }
  }
}

if (-not $entries -or $entries.Count -eq 0) {
  $zipObj.Dispose()
  @{ ok=@(); fail=@(@{Name='(none)';Message='No .REG selected'}) } | ConvertTo-Json -Compress
  exit 0
}

# 4) CHỌN reg.exe ĐÚNG
#   - PS 64-bit: dùng %WINDIR%\System32\reg.exe
#   - PS 32-bit trên OS 64-bit: dùng %WINDIR%\sysnative\reg.exe để truy cập reg.exe 64-bit
$regExe = Join-Path $env:WINDIR 'System32\reg.exe'
if (-not [Environment]::Is64BitProcess) {
  $sysnative = Join-Path $env:WINDIR 'sysnative\reg.exe'
  if (Test-Path -LiteralPath $sysnative) { $regExe = $sysnative }
}

# 5) Trích từng file ra thư mục tạm rồi import trực tiếp (bằng ProcessStartInfo để lấy ExitCode chuẩn)
if (Test-Path -LiteralPath $Temp) { Remove-Item -LiteralPath $Temp -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path $Temp -Force | Out-Null

$report = @()
foreach($e in $entries){
  try{
    $outFile = Join-Path $Temp $e.Name
    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($e, $outFile, $true)

    # Chạy reg.exe qua ProcessStartInfo - KHÔNG dùng backtick
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $regExe          # C:\Windows\System32\reg.exe hoặc sysnative\reg.exe
    $psi.Arguments              = ('import "{0}"' -f $outFile)   # <-- không có backtick
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $true

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    [void]$proc.Start()
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    $code = $proc.ExitCode
    $msg  = (($stderr + $stdout) | Out-String).Trim()

    # Một số bản reg.exe in "The operation completed successfully." dù code != 0
    $isSuccessText = ($msg -match 'completed successfully')
    if ($code -eq 0 -or $isSuccessText) {
      $report += @{ Name=$e.Name; Status='OK';  ExitCode=$code }
    } else {
      if (-not $msg) { $msg = "Exit code: $code" }
      $report += @{ Name=$e.Name; Status='FAIL'; ExitCode=$code; Message=$msg }
    }
  } catch {
    $report += @{ Name=$e.Name; Status='FAIL'; ExitCode=1; Message=$_.Exception.Message }
  }
}


$zipObj.Dispose()

@{
  ok   = @($report | Where-Object {$_.Status -eq 'OK'}  | ForEach-Object { $_.Name })
  fail = @($report | Where-Object {$_.Status -ne 'OK'}  | ForEach-Object { @{ Name = $_.Name; Message = $_.Message } })
  all  = $report
} | ConvertTo-Json -Compress
`;


  const psFile = path.join(os.tmpdir(), `restore-registry-${timeTag}.ps1`);
  fs.writeFileSync(psFile, ps, 'utf8');

  const r = await runPowerShellCommand(
    `powershell -NoProfile -ExecutionPolicy Bypass -File "${psFile}" -Zip "${it.source}" -Temp "${temp}" -AllowFile "${allowFile}"`
  );
  try { fs.rmSync(temp, { recursive: true, force: true }); } catch {}
  try { if (allowFile) fs.unlinkSync(allowFile); } catch {}
  try { fs.unlinkSync(psFile); } catch {}

  const raw = r.success ? (r.data || '') : (r.message || '');
  if (typeof raw === 'string' && raw.includes('__NEED_ADMIN__')) {
    results.push({ id: it.id, label: it.label, kind:'registry', success:false, message:'Yêu cầu chạy ứng dụng bằng quyền Administrator.' });
  } else if (r.success) {
    let parsed = null; try { parsed = JSON.parse(raw); } catch {}
    const okList   = Array.isArray(parsed?.ok)   ? parsed.ok   : [];
    const failList = Array.isArray(parsed?.fail) ? parsed.fail : [];
    results.push({
      id: it.id,
      label: it.label,
      kind: 'registry',
      success: okList.length > 0 && failList.length === 0,
      message: `Đã nhập ${okList.length} file .reg${failList.length ? `, lỗi ${failList.length}` : ''}`,
      regOk: okList,
      regFail: failList
    });
  } else {
    results.push({ id: it.id, label: it.label, kind:'registry', success:false, message: raw || 'Khôi phục Registry lỗi.' });
  }
}

      // --- Drivers (pnputil) ---
      else if (it.kind === 'drivers') {
        const timeTag = new Date().toISOString().replace(/\D/g, '').slice(0, 14);
        const temp = path.join(os.tmpdir(), `BBRestore-Drivers-${timeTag}`);
        if (!fs.existsSync(temp)) fs.mkdirSync(temp, { recursive: true });

        const ps = `
param([string]$Zip,[string]$Temp)
try {
  $wi  = [Security.Principal.WindowsIdentity]::GetCurrent()
  $wp  = New-Object Security.Principal.WindowsPrincipal($wi)
  $adm = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if(-not $adm){ Write-Output 'NEED_ADMIN'; exit 2 }
  Expand-Archive -Path $Zip -DestinationPath $Temp -Force
  $infs = Get-ChildItem -LiteralPath $Temp -Recurse -Filter *.inf -ErrorAction SilentlyContinue
  if(-not $infs){ Write-Output 'No INF found'; exit 3 }
  $ok=0; $fail=0
  foreach($f in $infs){
    $r = & pnputil.exe /add-driver "$($f.FullName)" /install 2>&1 | Out-String
    if($LASTEXITCODE -eq 0){ $ok++ } else { $fail++ }
  }
  "OK:$ok;FAIL:$fail"
} catch { Write-Output $_.Exception.Message; exit 1 }`;
        const psFile = path.join(os.tmpdir(), `restore-drivers-${timeTag}.ps1`);
        fs.writeFileSync(psFile, ps, 'utf8');
        const r = await runPowerShellCommand(
          `powershell -NoProfile -ExecutionPolicy Bypass -File "${psFile}" -Zip "${it.source}" -Temp "${temp}"`
        );
        try { fs.rmSync(temp, { recursive: true, force: true }); } catch (e) {}

        const msg = r.success ? (r.data || '') : (r.error || '');
        if (typeof msg === 'string' && msg.includes('NEED_ADMIN')) {
          results.push({ id: it.id, label: it.label, success: false, message: 'Yêu cầu chạy ứng dụng bằng quyền Administrator.' });
        } else if (r.success) {
          results.push({ id: it.id, label: it.label, success: true, message: msg || 'Đã cài lại driver (pnputil).' });
        } else {
          results.push({ id: it.id, label: it.label, success: false, message: msg || 'Khôi phục Drivers lỗi.' });
        }
      }

      else {
        results.push({ id: it.id, label: it.label, success: false, message: 'Loại gói không hỗ trợ.' });
      }
    } catch (err) {
      results.push({ id: it.id, label: it.label, success: false, message: err.message });
    }
  }

  return { success: true, results };
});
