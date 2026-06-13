/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/elevate"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
	"golang.zx2c4.com/wireguard/windows/services"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const filetimeToUnixOffset uint64 = 116444736000000000 // 100纳秒单位

type tunnelService struct {
	Path string
}

func (service *tunnelService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	serviceState := svc.StartPending
	changes <- svc.Status{State: serviceState}

	var watcher *interfaceWatcher
	var adapter *driver.Adapter
	var luid winipcfg.LUID
	var config *conf.Config
	var err error
	serviceError := services.ErrorSuccess

	defer func() {
		svcSpecificEC, exitCode = services.DetermineErrorCode(err, serviceError)
		logErr := services.CombineErrors(err, serviceError)
		if logErr != nil {
			log.Println(logErr)
		}
		serviceState = svc.StopPending
		changes <- svc.Status{State: serviceState}

		stopIt := make(chan bool, 1)
		go func() {
			t := time.NewTicker(time.Second * 30)
			for {
				select {
				case <-t.C:
					t.Stop()
					buf := make([]byte, 1024)
					for {
						n := runtime.Stack(buf, true)
						if n < len(buf) {
							buf = buf[:n]
							break
						}
						buf = make([]byte, 2*len(buf))
					}
					lines := bytes.Split(buf, []byte{'\n'})
					log.Println("Failed to shutdown after 30 seconds. Probably dead locked. Printing stack and killing.")
					for _, line := range lines {
						if len(bytes.TrimSpace(line)) > 0 {
							log.Println(string(line))
						}
					}
					os.Exit(777)
					return
				case <-stopIt:
					t.Stop()
					return
				}
			}
		}()

		if logErr == nil && adapter != nil && config != nil {
			logErr = runScriptCommand(config.Interface.PreDown, config.Name)
		}
		if watcher != nil {
			watcher.Destroy()
		}
		if adapter != nil {
			adapter.Close()
		}
		if logErr == nil && adapter != nil && config != nil {
			_ = runScriptCommand(config.Interface.PostDown, config.Name)
		}
		stopIt <- true
		log.Println("Shutting down")
	}()

	var logFile string
	logFile, err = conf.LogFile(true)
	if err != nil {
		serviceError = services.ErrorRingloggerOpen
		return
	}
	err = ringlogger.InitGlobalLogger(logFile, "TUN")
	if err != nil {
		serviceError = services.ErrorRingloggerOpen
		return
	}

	config, err = conf.LoadFromPath(service.Path)
	if err != nil {
		serviceError = services.ErrorLoadConfiguration
		return
	}
	config.DeduplicateNetworkEntries()

	log.SetPrefix(fmt.Sprintf("[%s] ", config.Name))

	services.PrintStarting()

	if services.StartedAtBoot() {
		if m, err := mgr.Connect(); err == nil {
			if lockStatus, err := m.LockStatus(); err == nil && lockStatus.IsLocked {
				/* If we don't do this, then the driver installation will block forever, because
				 * installing a network adapter starts the driver service too. Apparently at boot time,
				 * Windows 8.1 locks the SCM for each service start, creating a deadlock if we don't
				 * announce that we're running before starting additional services.
				 */
				log.Printf("SCM locked for %v by %s, marking service as started", lockStatus.Age, lockStatus.Owner)
				serviceState = svc.Running
				changes <- svc.Status{State: serviceState}
			}
			m.Disconnect()
		}
	}

	evaluateStaticPitfalls()

	log.Println("Watching network interfaces")
	watcher, err = watchInterface()
	if err != nil {
		serviceError = services.ErrorSetNetConfig
		return
	}

	log.Println("Resolving DNS names")
	err = config.ResolveEndpoints()
	if err != nil {
		serviceError = services.ErrorDNSLookup
		return
	}

	log.Println("Creating network adapter")
	for i := range 15 {
		if i > 0 {
			time.Sleep(time.Second)
			log.Printf("Retrying adapter creation after failure because system just booted (T+%v): %v", windows.DurationSinceBoot(), err)
		}
		adapter, err = driver.CreateAdapter(config.Name, "WireGuard", deterministicGUID(config))
		if err == nil || !services.StartedAtBoot() {
			break
		}
	}
	if err != nil {
		err = fmt.Errorf("Error creating adapter: %w", err)
		serviceError = services.ErrorCreateNetworkAdapter
		return
	}
	luid = adapter.LUID()
	driverVersion, err := driver.RunningVersion()
	if err != nil {
		log.Printf("Warning: unable to determine driver version: %v", err)
	} else {
		log.Printf("Using WireGuardNT/%d.%d", (driverVersion>>16)&0xffff, driverVersion&0xffff)
	}
	err = adapter.SetLogging(driver.AdapterLogOn)
	if err != nil {
		err = fmt.Errorf("Error enabling adapter logging: %w", err)
		serviceError = services.ErrorCreateNetworkAdapter
		return
	}

	err = runScriptCommand(config.Interface.PreUp, config.Name)
	if err != nil {
		serviceError = services.ErrorRunScript
		return
	}

	err = enableFirewall(config, luid)
	if err != nil {
		serviceError = services.ErrorFirewall
		return
	}

	log.Println("Dropping privileges")
	err = elevate.DropAllPrivileges(true)
	if err != nil {
		serviceError = services.ErrorDropPrivileges
		return
	}

	log.Println("Setting interface configuration")
	err = adapter.SetConfiguration(config.ToDriverConfiguration())
	if err != nil {
		serviceError = services.ErrorDeviceSetConfig
		return
	}
	err = adapter.SetAdapterState(driver.AdapterStateUp)
	if err != nil {
		serviceError = services.ErrorDeviceBringUp
		return
	}
	watcher.Configure(adapter, config, luid)

	err = runScriptCommand(config.Interface.PostUp, config.Name)
	if err != nil {
		serviceError = services.ErrorRunScript
		return
	}

	changes <- svc.Status{State: serviceState, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	//【20260531】增加远端节点超时重连功能。
	// ================= [新增代码：看门狗初始化] =================
	handshakeTicker := time.NewTicker(1 * time.Minute)
	defer handshakeTicker.Stop()
	var runningStartTime time.Time

	// 防抖与容灾状态变量
	var lastRecoveryAttempt time.Time
	var consecutiveFailures int                 // 连续失败/超时的次数
	const maxBackoffInterval = 30 * time.Minute // 最大退避上限
	// ==========================================================

	var started bool
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				return
			case svc.Interrogate:
				changes <- c.CurrentStatus
			default:
				log.Printf("Unexpected service control request #%d\n", c)
			}
		case <-watcher.started:
			if !started {
				serviceState = svc.Running
				changes <- svc.Status{State: serviceState, Accepts: svc.AcceptStop | svc.AcceptShutdown}
				log.Println("Startup complete")
				started = true
				//【20260531】
				// ================= [新增代码：记录启动时间] =================
				runningStartTime = time.Now()
				// ==========================================================
			}
		case e := <-watcher.errors:
			serviceError, err = e.serviceError, e.err
			return

		//【20260531】
		// ================= [新增代码：看门狗状态轮询与重连核心逻辑] =================
		case <-handshakeTicker.C:
			// 如果隧道还没有完全进入 Running 状态，跳过检查
			if !started {
				continue
			}

			// 1. 计算当前的动态退避延迟 (Exponential Backoff)
			// 公式: base_interval * (2 ^ consecutiveFailures)
			// 失败 0次: 3分钟后可查; 失败 1次: 4分钟; 失败 2次: 8分钟... 以此类推
			var currentBackoff time.Duration
			if consecutiveFailures == 0 {
				currentBackoff = 3 * time.Minute // 正常防抖间隔
			} else {
				// 指数递增，左移位实现 2 的 n 次方 (注意限制最大位移防止溢出)
				shift := consecutiveFailures - 1
				if shift > 10 {
					shift = 10
				}
				currentBackoff = time.Duration(1<<shift) * 2 * time.Minute
			}

			// 限制最大退避时长，防止永久失联
			if currentBackoff > maxBackoffInterval {
				currentBackoff = maxBackoffInterval
			}

			// 【20260613】：防抖验证，距离上一次重置操作不足 3 分钟时，忽略本次检查，防止死循环
			if !lastRecoveryAttempt.IsZero() && time.Since(lastRecoveryAttempt) < currentBackoff {
				continue
			}

			// 1. 向驱动层索取当前的接口状态 (返回 *driver.Interface)
			iface, err := adapter.Configuration()
			if err != nil {
				log.Printf("Watchdog: Failed to get adapter configuration: %v", err)
				continue
			}

			needsReconfig := false

			// 2. 遍历底层的 Peer 状态
			// 【20260613】：将初始化提至循环外，防止逻辑误判
			p := iface.FirstPeer()
			for i := uint32(0); i < iface.PeerCount; i++ {
				if p == nil {
					log.Printf("Watchdog: Encountered nil peer at index %d, aborting traversal", i)
					break
				}

				// 情况 A：从未成功握手过
				if p.LastHandshake == 0 {
					if time.Since(runningStartTime) > 3*time.Minute {
						log.Printf("Watchdog: No initial handshake for peer %d over 3 minutes. Triggering re-configuration.", i)
						needsReconfig = true
						break
					}
				} else {
					// 情况 B：曾经握手过。
					if p.LastHandshake < filetimeToUnixOffset {
						log.Printf("Watchdog: Invalid LastHandshake value (%d) for peer %d", p.LastHandshake, i)
						continue
					}

					unixNano := int64(p.LastHandshake-filetimeToUnixOffset) * 100
					handshakeTime := time.Unix(0, unixNano)

					// 检查距离上次握手是否超过 3 分钟
					if time.Since(handshakeTime) > 3*time.Minute {
						log.Printf("Watchdog: Handshake timed out (>3 mins) for peer %d. Last: %v", i, handshakeTime.Format(time.RFC3339))
						needsReconfig = true
						break
					}
				}
				// 步进至下一个节点
				p = p.NextPeer()
			}

			// 3. 执行平滑重配置
			if needsReconfig {
				log.Println("Watchdog: Triggering connection recovery process...")

				// 【20260613】：重新从磁盘加载配置，捕获运行期间通过 GUI 产生的更改
				newConfig, loadErr := conf.LoadFromPath(service.Path)
				if loadErr != nil {
					log.Printf("Watchdog: Failed to reload configuration from disk: %v", loadErr)
					continue
				}
				newConfig.DeduplicateNetworkEntries()

				// 【20260613】：基于新配置重新解析 DNS（解决 DDNS 导致 IP 变更的问题）
				log.Println("Watchdog: Re-resolving endpoints")
				if dnsErr := newConfig.ResolveEndpoints(); dnsErr != nil {
					log.Printf("Watchdog: Failed to resolve endpoints: %v", dnsErr)
					// 如果 DNS 解析失败，跳过本次重试，等待下一分钟
					continue
				}

				// 将新的配置对象替换为全局使用的配置
				config = newConfig

				// 【20260531】：下发配置。
				// 注：WireGuardNT 驱动处理 SetConfiguration 时使用基于公钥的 Diff 逻辑。
				// 它会静默更新 IP 变更或新增的节点，不会影响配置未改变的正常活跃节点，达到“无感重连”。
				log.Println("Watchdog: Applying updated configuration to driver to recover peer connection...")
				applyErr := adapter.SetConfiguration(config.ToDriverConfiguration())
				if applyErr != nil {
					consecutiveFailures++
					log.Printf("Watchdog: Failed to apply configuration (Attempt %d/3): %v", consecutiveFailures, applyErr)

					// 严重故障依然保留熔断机制（可选，如果你希望它无限退避重试，可以去掉这段）
					// if consecutiveFailures >= 10 {
					// 	log.Println("Watchdog: Critical failure limit reached. Terminating service for SCM recovery.")
					// 	err = applyErr
					// 	serviceError = services.ErrorDeviceSetConfig
					// 	return
					// }
				} else {
					// 成功后重置计数器和防抖时间戳
					consecutiveFailures = 0
					lastRecoveryAttempt = time.Now()
					log.Println("Watchdog: Recovery configuration applied successfully")
				}
			} else {
				// 【20260613】：如果检测到所有节点正常活跃，也重置退避计数器（意味着网络已经自我恢复）
				if consecutiveFailures > 0 {
					log.Println("Watchdog: Connection healthy, resetting failure counter")
				}
				consecutiveFailures = 0
			}
			// =========================================================================
		}
	}
}

func Run(confPath string) error {
	name, err := conf.NameFromPath(confPath)
	if err != nil {
		return err
	}
	serviceName, err := conf.ServiceNameOfTunnel(name)
	if err != nil {
		return err
	}
	return svc.Run(serviceName, &tunnelService{confPath})
}
