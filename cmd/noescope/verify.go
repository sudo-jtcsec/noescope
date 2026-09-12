package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sudo-jtcsec/noescope/internal/authn"
	"github.com/sudo-jtcsec/noescope/internal/config"
	"github.com/sudo-jtcsec/noescope/internal/repository"
	"github.com/sudo-jtcsec/noescope/internal/runtimeverify"
	"github.com/sudo-jtcsec/noescope/internal/runtimeverify/browser"
)

func verifyCommand() *cobra.Command {
	var sourceRunID string
	var maxInterfaces int
	command := &cobra.Command{
		Use:   "verify",
		Short: "Verify source-discovered functionality against a running application",
		RunE: func(cmd *cobra.Command, args []string) error {
			if maxInterfaces <= 0 {
				return fmt.Errorf("--max-interfaces must be greater than zero")
			}
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			configPath, err := config.Find(cwd)
			if err != nil {
				return err
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			if cfg.Runtime.BaseURL == "" {
				return fmt.Errorf("runtime.base_url or application.url must be configured in noescope.yml")
			}
			projectRoot := filepath.Dir(configPath)
			repo, err := repository.Open(filepath.Join(projectRoot, cfg.Source.Path))
			if err != nil {
				return err
			}
			repoInfo, err := repo.Info()
			if err != nil {
				return err
			}
			source, err := runtimeverify.LoadSourceModel(
				projectRoot, sourceRunID, repoInfo.Root, repoInfo.Commit,
			)
			if err != nil {
				return err
			}

			var credentials *browser.Credentials
			var totpReference *authn.TOTPReference
			secrets := make([]string, 0, 2)
			if cfg.Runtime.Identity != "" {
				identity, err := cfg.Identity(cfg.Runtime.Identity)
				if err != nil {
					return err
				}
				resolved, err := identity.ResolveCredentials(os.LookupEnv)
				if err != nil {
					return err
				}
				credentials = &browser.Credentials{
					Username: resolved.Username, Password: resolved.Password,
				}
				if identity.TOTP != nil {
					totpReference = &authn.TOTPReference{SecretEnv: identity.TOTP.SecretEnv,
						Period: identity.TOTP.Period, Digits: identity.TOTP.Digits, Algorithm: identity.TOTP.Algorithm}
				}
				secrets = append(secrets, resolved.Username, resolved.Password)
			}

			session, err := runtimeverify.NewSession(
				source.Run.Root, source.Application, cfg.Runtime.BaseURL,
			)
			if err != nil {
				return err
			}
			redactor := runtimeverify.NewRedactor(secrets...)
			evidenceStore := runtimeverify.NewEvidenceStore(session.Root, redactor)
			browserEngine, err := browser.NewChrome(cmd.Context(), browser.Options{
				Headless:        cfg.Runtime.Browser.Headless,
				IgnoreTLSErrors: cfg.Runtime.Browser.IgnoreTLSErrors,
				ExecutablePath:  cfg.Runtime.Browser.Executable,
			})
			if err != nil {
				record, evidenceErr := evidenceStore.Add(runtimeverify.EvidenceRecord{
					Kind: "runtime_assertion", Summary: "Chromium failed to start: " + redactor.String(err.Error()),
				})
				if evidenceErr == nil {
					runtimeverify.MarkFailure(
						session.Runtime, "browser", "start",
						redactor.String(err.Error()), []string{record.ID},
					)
					session.Runtime.Application = runtimeverify.ApplicationObservation{
						Reachable: false, Status: runtimeverify.StatusRuntimeError,
						EvidenceIDs: []string{record.ID},
					}
					session.Runtime.Authentication = runtimeverify.AuthenticationObservation{
						Attempted: false, Status: runtimeverify.StatusNotAttempted,
						Identity: cfg.Runtime.Identity, Reason: "Chromium did not start",
						EvidenceIDs: []string{record.ID},
					}
					for _, item := range source.Application.Surface.Interfaces {
						classification := runtimeverify.ClassifyInterface(item)
						session.Runtime.Interfaces = append(
							session.Runtime.Interfaces,
							runtimeverify.InterfaceObservation{
								InterfaceID: item.ID, State: "not_attempted",
								Safety: classification.Safety, Status: runtimeverify.StatusNotAttempted,
								Reason: "Chromium did not start", EvidenceIDs: []string{record.ID},
							},
						)
					}
					session.Runtime.Features = runtimeverify.FeatureCoverage(
						source.Application, session.Runtime.Interfaces,
					)
					_, _, _ = session.Write()
				}
				return err
			}

			fmt.Printf("Source run:  %s\n", source.Run.ID)
			fmt.Printf("Runtime run: %s\n", session.Runtime.RuntimeID)
			fmt.Printf("Target:      %s\n\n", session.Runtime.BaseURL)
			verifyErr := runtimeverify.Verify(cmd.Context(), runtimeverify.VerifyOptions{
				Application: source.Application, Runtime: session.Runtime,
				RuntimeRoot: session.Root, Browser: browserEngine,
				Evidence: evidenceStore, Redactor: redactor,
				IdentityID: cfg.Runtime.Identity, Credentials: credentials,
				TOTP: totpReference, LookupEnv: os.LookupEnv,
				MaxInterfaces: maxInterfaces,
				Logf:          func(format string, args ...any) { fmt.Printf(format+"\n", args...) },
			})
			if verifyErr != nil && session.Runtime.Status != runtimeverify.RunStatusFailed &&
				session.Runtime.Status != runtimeverify.RunStatusPartial {
				runtimeverify.MarkFailure(
					session.Runtime, "runtime", "verification",
					redactor.String(verifyErr.Error()), nil,
				)
			}
			jsonPath, markdownPath, writeErr := session.Write()
			if writeErr != nil {
				return writeErr
			}
			fmt.Printf("Runtime model written to:\n%s\n\nRuntime report written to:\n%s\n", jsonPath, markdownPath)
			if verifyErr != nil {
				return verifyErr
			}
			return nil
		},
	}
	command.Flags().StringVar(&sourceRunID, "run", "", "source discovery run ID (defaults to latest compatible complete run)")
	command.Flags().IntVar(&maxInterfaces, "max-interfaces", 10, "maximum safe source interfaces to visit")
	return command
}
