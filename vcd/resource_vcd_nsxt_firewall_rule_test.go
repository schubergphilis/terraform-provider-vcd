//go:build network || nsxt || functional || ALL

package vcd

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccVcdNsxtFirewallRule_Basic(t *testing.T) {
	preTestChecks(t)

	ruleName := "test-acc-firewall-rule-basic"
	resourceName := "vcd_nsxt_firewall_rule.test"

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviders,
		CheckDestroy:      testAccCheckVcdNsxtFirewallRuleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccVcdNsxtFirewallRuleConfig(ruleName, "ALLOW", "IN_OUT"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckVcdNsxtFirewallRuleExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", ruleName),
					resource.TestCheckResourceAttr(resourceName, "action", "ALLOW"),
					resource.TestCheckResourceAttr(resourceName, "direction", "IN_OUT"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "logging", "false"),
					resource.TestCheckResourceAttr(resourceName, "ip_protocol", "IPV4"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: testAccVcdNsxtFirewallRuleImportStateIdFunc(resourceName),
			},
			{
				Config: testAccVcdNsxtFirewallRuleConfig(ruleName+"-updated", "DROP", "IN"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckVcdNsxtFirewallRuleExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", ruleName+"-updated"),
					resource.TestCheckResourceAttr(resourceName, "action", "DROP"),
					resource.TestCheckResourceAttr(resourceName, "direction", "IN"),
				),
			},
		},
	})
}

func TestAccVcdNsxtFirewallRule_Complete(t *testing.T) {
	preTestChecks(t)

	ruleName := "test-acc-firewall-rule-complete"
	resourceName := "vcd_nsxt_firewall_rule.test"

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviders,
		CheckDestroy:      testAccCheckVcdNsxtFirewallRuleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccVcdNsxtFirewallRuleCompleteConfig(ruleName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckVcdNsxtFirewallRuleExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", ruleName),
					resource.TestCheckResourceAttr(resourceName, "action", "ALLOW"),
					resource.TestCheckResourceAttr(resourceName, "direction", "IN_OUT"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "logging", "true"),
					resource.TestCheckResourceAttr(resourceName, "ip_protocol", "IPV4_IPV6"),
					resource.TestCheckResourceAttr(resourceName, "source_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "destination_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "app_port_profile_ids.#", "1"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: testAccVcdNsxtFirewallRuleImportStateIdFunc(resourceName),
			},
		},
	})
}

func testAccVcdNsxtFirewallRuleCompleteConfig(name string) string {
	return fmt.Sprintf(`
		data "vcd_org" "test" {
			name = "%s"
		}

		data "vcd_nsxt_edgegateway" "test" {
			org = data.vcd_org.test.name
			name = "%s"
		}

		resource "vcd_nsxt_ip_set" "src" {
			edge_gateway_id = data.vcd_nsxt_edgegateway.test.id
			name            = "%s-src"
			ip_addresses    = ["1.1.1.1"]
		}

		resource "vcd_nsxt_security_group" "dst" {
			edge_gateway_id = data.vcd_nsxt_edgegateway.test.id
			name            = "%s-dst"
		}

		resource "vcd_nsxt_app_port_profile" "app" {
			org             = data.vcd_org.test.name
			name            = "%s-app"
			scope           = "TENANT"
			app_port {
				protocol = "TCP"
				port     = ["443"]
			}
		}

		resource "vcd_nsxt_firewall_rule" "test" {
			org             = data.vcd_org.test.name
			edge_gateway_id = data.vcd_nsxt_edgegateway.test.id
			name            = "%s"
			action          = "ALLOW"
			direction       = "IN_OUT"
			enabled         = true
			logging         = true
			ip_protocol     = "IPV4_IPV6"

			source_ids           = [vcd_nsxt_ip_set.src.id]
			destination_ids      = [vcd_nsxt_security_group.dst.id]
			app_port_profile_ids = [vcd_nsxt_app_port_profile.app.id]
		}
	`, testConfig.VCD.Org, testConfig.Nsxt.EdgeGateway, name, name, name, name)
}

func testAccCheckVcdNsxtFirewallRuleDestroy(s *terraform.State) error {
	vcdClient := testAccProvider.Meta().(*VCDClient)
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vcd_nsxt_firewall_rule" {
			continue
		}

		orgName := rs.Primary.Attributes["org"]
		edgeGatewayId := rs.Primary.Attributes["edge_gateway_id"]
		ruleId := rs.Primary.ID

		egw, err := vcdClient.GetNsxtEdgeGatewayById(orgName, edgeGatewayId)
		if err != nil {
			return err
		}

		firewall, err := egw.GetNsxtFirewall()
		if err != nil {
			return err
		}

		for _, rule := range firewall.NsxtFirewallRuleContainer.UserDefinedRules {
			if rule.ID == ruleId {
				return fmt.Errorf("NSX-T Firewall Rule %s still exists", ruleId)
			}
		}
	}
	return nil
}

func testAccCheckVcdNsxtFirewallRuleExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("no NSX-T Firewall Rule ID is set")
		}

		vcdClient := testAccProvider.Meta().(*VCDClient)
		orgName := rs.Primary.Attributes["org"]
		edgeGatewayId := rs.Primary.Attributes["edge_gateway_id"]

		egw, err := vcdClient.GetNsxtEdgeGatewayById(orgName, edgeGatewayId)
		if err != nil {
			return err
		}

		firewall, err := egw.GetNsxtFirewall()
		if err != nil {
			return err
		}

		found := false
		for _, rule := range firewall.NsxtFirewallRuleContainer.UserDefinedRules {
			if rule.ID == rs.Primary.ID {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("NSX-T Firewall Rule %s not found", rs.Primary.ID)
		}

		return nil
	}
}

func testAccVcdNsxtFirewallRuleImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return fmt.Sprintf("%s.%s", rs.Primary.Attributes["edge_gateway_id"], rs.Primary.ID), nil
	}
}

func testAccVcdNsxtFirewallRuleConfig(name, action, direction string) string {
	return fmt.Sprintf(`
		data "vcd_org" "test" {
			name = "%s"
		}

		data "vcd_nsxt_edgegateway" "test" {
			org = data.vcd_org.test.name
			name = "%s"
		}

		resource "vcd_nsxt_firewall_rule" "test" {
			org             = data.vcd_org.test.name
			edge_gateway_id = data.vcd_nsxt_edgegateway.test.id
			name            = "%s"
			action          = "%s"
			direction       = "%s"
			ip_protocol     = "IPV4"
		}
	`, testConfig.VCD.Org, testConfig.Nsxt.EdgeGateway, name, action, direction)
}
