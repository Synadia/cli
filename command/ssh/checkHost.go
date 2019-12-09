package ssh

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
)

func checkHostCommand() cli.Command {
	return cli.Command{
		Name:   "check-host",
		Action: command.ActionFunc(checkHostAction),
		Usage:  "checks if a certificate has been issued for a host",
		UsageText: `**step ssh check-host** <hostname>
		[**--ca-url**=<uri>] [**--root**=<file>]
		[**--offline**] [**--ca-config**=<path>]`,
		Description: `**step ssh check-host** checks if a certificate has been issued for a host.

This command returns a zero exit status then the server exists, it will return 1
otherwise.

## POSITIONAL ARGUMENTS

<hostname>
:  The hostname of the server to check.

## EXAMPLES

Check that internal.example.com exists:
'''
$ step ssh check-host internal.smallstep.com
'''`,
		Flags: []cli.Flag{
			flags.CaURL,
			flags.Root,
			flags.Offline,
			flags.CaConfig,
		},
	}
}

func checkHostAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	// Prepare retry function
	retryFunc, err := loginOnUnauthorized(ctx)
	if err != nil {
		return err
	}

	client, err := cautils.NewClient(ctx, ca.WithRetryFunc(retryFunc))
	if err != nil {
		return err
	}

	id, err := ca.LoadDefaultIdentity()
	if err != nil {
		return errors.Wrap(err, "error loading the deault x5c identity")
	}

	var token string
	if id != nil {
		// Get private key from given key file
		jwk, err := jose.ParseKey(id.Key)
		if err != nil {
			return err
		}
		tokenGen := cautils.NewTokenGenerator(jwk.KeyID, "x5c-identity",
			"/ssh/check-host", "", tokAttrs.notBefore, tokAttrs.notAfter, jwk)
		token, err = tokenGen.Token(tokAttrs.subject, token.WithX5CFile(id.Certificate, jwk.Key))
		if err != nil {
			return errors.Wrap(err, "error generating idenityt x5c token for /ssh/check-host request")
		}
	}

	resp, err := client.SSHCheckHost(ctx.Args().First(), token)
	if err != nil {
		return err
	}

	fmt.Println(resp.Exists)
	if !resp.Exists {
		os.Exit(1)
	}
	return nil
}
