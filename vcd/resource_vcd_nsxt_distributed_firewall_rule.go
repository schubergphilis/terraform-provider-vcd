package vcd

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/vmware/go-vcloud-director/v2/govcd"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
)

func resourceVcdNsxtDistributedFirewallRule() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceVcdNsxtDistributedFirewallRuleCreate,
		ReadContext:   resourceVcdNsxtDistributedFirewallRuleRead,
		UpdateContext: resourceVcdNsxtDistributedFirewallRuleUpdate,
		DeleteContext: resourceVcdNsxtDistributedFirewallRuleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceVcdNsxtDistributedFirewallRuleImport,
		},

		Schema: map[string]*schema.Schema{
			"org": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Description: "The name of organization to use, optional if defined at provider " +
					"level. Useful when connected as sysadmin working across different organizations",
			},
			"vdc_group_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "ID of VDC Group for Distributed Firewall",
			},
			"above_rule_id": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "An optional firewall rule ID, to put new rule above during creation",
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Firewall Rule name",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description is not shown in UI",
			},
			"comment": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Comment that is shown next to rule in UI (VCD 10.3.2+)",
			},
			"direction": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "Direction on which Firewall Rule applies (one of 'IN', 'OUT', 'IN_OUT')",
				Default:      "IN_OUT",
				ValidateFunc: validation.StringInSlice([]string{"IN", "OUT", "IN_OUT"}, false),
			},
			"ip_protocol": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "Firewall Rule Protocol (one of 'IPV4', 'IPV6', 'IPV4_IPV6')",
				Default:      "IPV4_IPV6",
				ValidateFunc: validation.StringInSlice([]string{"IPV4", "IPV6", "IPV4_IPV6"}, false),
			},
			"action": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Defines if the rule should 'ALLOW', 'DROP', 'REJECT' matching traffic",
				ValidateFunc: validation.StringInSlice([]string{"ALLOW", "DROP", "REJECT"}, false),
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Defined if Firewall Rule is active",
			},
			"logging": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Defines if matching traffic should be logged",
			},
			"source_ids": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A set of Source Firewall Group IDs (IP Sets or Security Groups). Leaving it empty means 'Any'",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"destination_ids": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A set of Destination Firewall Group IDs (IP Sets or Security Groups). Leaving it empty means 'Any'",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"app_port_profile_ids": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A set of Application Port Profile IDs. Leaving it empty means 'Any'",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"network_context_profile_ids": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A set of Network Context Profile IDs. Leaving it empty means 'Any'",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"source_groups_excluded": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Reverses firewall matching for to match all except Source Groups specified in 'source_ids' (VCD 10.3.2+)",
			},
			"destination_groups_excluded": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Reverses firewall matching for to match all except Destinations Groups specified in 'destination_ids' (VCD 10.3.2+)",
			},
		},
	}
}

func resourceVcdNsxtDistributedFirewallRuleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	vcdClient := meta.(*VCDClient)
	vcdClient.lockParentVdcGroup(d)
	defer vcdClient.unlockParentVdcGroup(d)

	org, err := vcdClient.GetOrgFromResource(d)
	if err != nil {
		return diag.Errorf("[Distributed Firewall Rule create] error retrieving Org: %s", err)
	}

	vdcGroup, err := org.GetVdcGroupById(d.Get("vdc_group_id").(string))
	if err != nil {
		return diag.Errorf("[Distributed Firewall Rule create] error retrieving VDC Group: %s", err)
	}

	firewallRuleType, err := getDistributedFirewallRuleType(vcdClient, d, "create")
	if err != nil {
		return diag.Errorf("[Distributed Firewall Rule create] error getting Distributed Firewall Rule type: %s", err)
	}
	singleRule, err := createDistributedFirewallRuleWithVerification(vdcGroup, d.Get("above_rule_id").(string), firewallRuleType)
	if err != nil {
		return diag.Errorf("[Distributed Firewall Rule create] error setting Distributed Firewall Rule: %s", err)
	}

	d.SetId(singleRule.Rule.ID)

	return resourceVcdNsxtDistributedFirewallRuleRead(ctx, d, meta)
}

// dfwRuleCreateVerifyAttempts bounds how many times createDistributedFirewallRuleWithVerification
// retries after a lost update before giving up.
const dfwRuleCreateVerifyAttempts = 5

// createDistributedFirewallRuleWithVerification creates a Distributed Firewall Rule and then
// confirms it actually landed in the requested position before returning.
//
// CreateDistributedFirewallRule works by reading the *entire* rule list for the VDC group, splicing
// in the new rule, and writing the whole list back - there is no compare-and-swap on that endpoint
// (see its own doc comment: "Running this function concurrently will corrupt firewall rules"). A VDC
// group's DFW policy is commonly shared across several independent teams/pipelines, each with their
// own Terraform run; the in-process 'lockParentVdcGroup' mutex only serializes goroutines within
// this one provider process, so it cannot prevent a concurrent writer in another process from
// reading a stale list at the same time and overwriting our just-added rule, silently dropping it or
// leaving it below 'above_rule_id'. Detect that by re-reading the rule list after create and
// retrying (from scratch, since the anchor may have moved) if our rule isn't where we asked for it.
func createDistributedFirewallRuleWithVerification(vdcGroup *govcd.VdcGroup, aboveRuleId string, firewallRuleType *types.DistributedFirewallRule) (*govcd.DistributedFirewallRule, error) {
	var lastErr error
	for attempt := 1; attempt <= dfwRuleCreateVerifyAttempts; attempt++ {
		_, singleRule, err := vdcGroup.CreateDistributedFirewallRule(aboveRuleId, firewallRuleType)
		if err != nil {
			return nil, err
		}

		inPosition, err := distributedFirewallRuleIsInExpectedPosition(vdcGroup, singleRule.Rule.ID, aboveRuleId)
		if err != nil {
			return nil, fmt.Errorf("error verifying position of newly created Distributed Firewall Rule: %s", err)
		}
		if inPosition {
			return singleRule, nil
		}

		log.Printf("[DEBUG] [Distributed Firewall Rule create] rule '%s' was not found in its expected "+
			"position after create (attempt %d/%d) - a concurrent writer likely overwrote the shared rule "+
			"list. Removing it and retrying.", singleRule.Rule.ID, attempt, dfwRuleCreateVerifyAttempts)

		// Clean up whatever landed in the wrong spot (if it still exists at all) before retrying, so
		// retries don't accumulate duplicate/orphaned rules.
		if existingRule, getErr := vdcGroup.GetDistributedFirewallRuleById(singleRule.Rule.ID); getErr == nil {
			_ = existingRule.Delete()
		}

		lastErr = fmt.Errorf("rule was not in its expected position")
		time.Sleep(time.Duration(attempt) * 2 * time.Second)
	}

	return nil, fmt.Errorf("gave up creating Distributed Firewall Rule in its expected position after %d attempts: %s",
		dfwRuleCreateVerifyAttempts, lastErr)
}

// distributedFirewallRuleIsInExpectedPosition reports whether 'ruleId' is present in the VDC
// Group's Distributed Firewall Rule list and, when 'aboveRuleId' is set, that it appears before it.
func distributedFirewallRuleIsInExpectedPosition(vdcGroup *govcd.VdcGroup, ruleId, aboveRuleId string) (bool, error) {
	dfw, err := vdcGroup.GetDistributedFirewall()
	if err != nil {
		return false, err
	}

	ruleIndex := -1
	aboveRuleIndex := -1
	for index, rule := range dfw.DistributedFirewallRuleContainer.Values {
		if rule.ID == ruleId {
			ruleIndex = index
		}
		if aboveRuleId != "" && rule.ID == aboveRuleId {
			aboveRuleIndex = index
		}
	}

	if ruleIndex == -1 {
		return false, nil
	}
	if aboveRuleId != "" && (aboveRuleIndex == -1 || ruleIndex >= aboveRuleIndex) {
		return false, nil
	}

	return true, nil
}

func resourceVcdNsxtDistributedFirewallRuleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	vcdClient := meta.(*VCDClient)
	vcdClient.lockParentVdcGroup(d)
	defer vcdClient.unlockParentVdcGroup(d)

	org, err := vcdClient.GetOrgFromResource(d)
	if err != nil {
		return diag.Errorf("[Distributed Firewall Rule update] error retrieving Org: %s", err)
	}

	vdcGroup, err := org.GetVdcGroupById(d.Get("vdc_group_id").(string))
	if err != nil {
		return diag.Errorf("[Distributed Firewall Rule update] error retrieving VDC Group: %s", err)
	}

	rule, err := vdcGroup.GetDistributedFirewallRuleById(d.Id())
	if err != nil {
		return diag.Errorf("[Distributed Firewall Rule update] error retrieving Firewall Rule By ID: %s", err)
	}

	firewallRuleType, err := getDistributedFirewallRuleType(vcdClient, d, "create")
	if err != nil {
		return diag.Errorf("[Distributed Firewall Rule update] error getting Distributed Firewall Rule type: %s", err)
	}

	firewallRuleType.ID = rule.Rule.ID
	_, err = rule.Update(firewallRuleType)
	if err != nil {
		return diag.Errorf("[Distributed Firewall Rule update] errorupdating Distributed Firewall Rule: %s", err)
	}

	return resourceVcdNsxtDistributedFirewallRuleRead(ctx, d, meta)
}

func resourceVcdNsxtDistributedFirewallRuleRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	vcdClient := meta.(*VCDClient)

	org, err := vcdClient.GetOrgFromResource(d)
	if err != nil {
		return diag.Errorf("[Distributed Firewall Rule read] error retrieving Org: %s", err)
	}

	vdcGroup, err := org.GetVdcGroupById(d.Get("vdc_group_id").(string))
	if err != nil {
		return diag.Errorf("[Distributed Firewall Rule read] error retrieving VDC Group: %s", err)
	}

	rule, err := vdcGroup.GetDistributedFirewallRuleById(d.Id())
	if err != nil {
		if govcd.ContainsNotFound(err) {
			d.SetId("")
		}
		return diag.Errorf("[Distributed Firewall Rule read] error retrieving Firewall Rule By ID: %s", err)
	}

	err = setDistributedFirewallRuleData(rule.Rule, d)
	if err != nil {
		return diag.Errorf("error storing data to state: %s", err)
	}

	return nil
}

func resourceVcdNsxtDistributedFirewallRuleDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	vcdClient := meta.(*VCDClient)
	vcdClient.lockParentVdcGroup(d)
	defer vcdClient.unlockParentVdcGroup(d)

	org, err := vcdClient.GetOrgFromResource(d)
	if err != nil {
		return diag.Errorf("[Distributed Firewall Rule delete] error retrieving Org: %s", err)
	}

	vdcGroup, err := org.GetVdcGroupById(d.Get("vdc_group_id").(string))
	if err != nil {
		return diag.Errorf("[Distributed Firewall Rule delete] error retrieving VDC Group: %s", err)
	}

	// Get existing rule
	rule, err := vdcGroup.GetDistributedFirewallRuleById(d.Id())
	if err != nil {
		return diag.Errorf("[Distributed Firewall Rule delete] error retrieving Firewall Rule By ID: %s", err)
	}

	err = rule.Delete()
	if err != nil {
		return diag.Errorf("[Distributed Firewall Rule delete] error deleting Firewall Rule By ID: %s", err)
	}

	return nil
}

func resourceVcdNsxtDistributedFirewallRuleImport(_ context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	log.Printf("[TRACE] NSX-T Distributed Firewall Rule import initiated")

	resourceURI := strings.Split(d.Id(), ImportSeparator)
	if len(resourceURI) != 3 {
		return nil, fmt.Errorf("resource name must be specified as org-name.vdc-group-name.fw-rule-name")
	}

	orgName, vdcGroupName, fwRuleName := resourceURI[0], resourceURI[1], resourceURI[2]

	vcdClient := meta.(*VCDClient)
	adminOrg, err := vcdClient.GetAdminOrg(orgName)
	if err != nil {
		return nil, fmt.Errorf("[Distributed Firewall Rule Import] error retrieving org %s: %s", orgName, err)
	}

	vdcGroup, err := adminOrg.GetVdcGroupByName(vdcGroupName)
	if err != nil {
		return nil, fmt.Errorf("[Distributed Firewall Rule Import] error importing VDC group item: %s", err)
	}

	fwRule, err := vdcGroup.GetDistributedFirewallRuleByName(fwRuleName)
	if err != nil {
		return nil, fmt.Errorf("could not find Distributed Firewall Rule by Name: %s", err)
	}

	d.SetId(fwRule.Rule.ID)
	dSet(d, "org", orgName)
	dSet(d, "vdc_group_id", vdcGroup.VdcGroup.Id)

	return []*schema.ResourceData{d}, nil
}

func getDistributedFirewallRuleType(vcdClient *VCDClient, d *schema.ResourceData, operation string) (*types.DistributedFirewallRule, error) {
	ressss := &types.DistributedFirewallRule{
		Name:        d.Get("name").(string),
		Description: d.Get("description").(string),
		ActionValue: d.Get("action").(string),
		Enabled:     d.Get("enabled").(bool),
		IpProtocol:  d.Get("ip_protocol").(string),
		Logging:     d.Get("logging").(bool),
		Direction:   d.Get("direction").(string),
		Version:     nil,
	}

	sourceGroupIds := convertSchemaSetToSliceOfStrings(d.Get("source_ids").(*schema.Set))
	ressss.SourceFirewallGroups = convertSliceOfStringsToOpenApiReferenceIds(sourceGroupIds)

	destinationGroupIds := convertSchemaSetToSliceOfStrings(d.Get("destination_ids").(*schema.Set))
	ressss.DestinationFirewallGroups = convertSliceOfStringsToOpenApiReferenceIds(destinationGroupIds)

	appPortProfileIds := convertSchemaSetToSliceOfStrings(d.Get("app_port_profile_ids").(*schema.Set))
	ressss.ApplicationPortProfiles = convertSliceOfStringsToOpenApiReferenceIds(appPortProfileIds)

	networkContextPortProfileIds := convertSchemaSetToSliceOfStrings(d.Get("network_context_profile_ids").(*schema.Set))
	ressss.NetworkContextProfiles = convertSliceOfStringsToOpenApiReferenceIds(networkContextPortProfileIds)

	comment := d.Get("comment").(string)
	sourceGroupsExcluded := d.Get("source_groups_excluded").(bool)
	destinationGroupsExcluded := d.Get("destination_groups_excluded").(bool)
	if vcdClient.Client.APIVCDMaxVersionIs(">= 36.2") {
		ressss.Comments = comment

		if sourceGroupsExcluded {
			ressss.SourceGroupsExcluded = &sourceGroupsExcluded
		}

		if destinationGroupsExcluded {
			ressss.DestinationGroupsExcluded = &destinationGroupsExcluded
		}
	} else {
		if comment != "" {
			return nil, fmt.Errorf("field 'comment' can only be set in VCD 10.3.2+")
		}

		// Two below checks will only throw an error if 'true' value has been set. False
		// will be ignored (when either set, or not set at all), because the only somewhat
		// reliable way is to use d.GetOkExists which has been deprecated in SDK with no
		// reliable replacement. There is no real need to use it here so just leaving one
		// less place to fix in future if d.GetOkExists is removed from SDK.
		if sourceGroupsExcluded {
			return nil, fmt.Errorf("field 'source_groups_excluded' can only be enabled in VCD 10.3.2+")
		}

		if destinationGroupsExcluded {
			return nil, fmt.Errorf("field 'source_groups_excluded' can only be enabled in VCD 10.3.2+")
		}
	}

	return ressss, nil
}

func setDistributedFirewallRuleData(dfwRule *types.DistributedFirewallRule, d *schema.ResourceData) error {
	dSet(d, "name", dfwRule.Name)
	dSet(d, "description", dfwRule.Description)
	dSet(d, "comment", dfwRule.Comments)
	dSet(d, "action", dfwRule.ActionValue)
	dSet(d, "enabled", dfwRule.Enabled)
	dSet(d, "ip_protocol", dfwRule.IpProtocol)
	dSet(d, "direction", dfwRule.Direction)
	dSet(d, "logging", dfwRule.Logging)
	dSet(d, "source_groups_excluded", dfwRule.SourceGroupsExcluded)
	dSet(d, "destination_groups_excluded", dfwRule.DestinationGroupsExcluded)

	sourceSlice := extractIdsFromOpenApiReferences(dfwRule.SourceFirewallGroups)
	sourceSet := convertStringsToTypeSet(sourceSlice)
	err := d.Set("source_ids", sourceSet)
	if err != nil {
		return fmt.Errorf("error storing 'source_ids':%s", err)
	}

	destinationSlice := extractIdsFromOpenApiReferences(dfwRule.DestinationFirewallGroups)
	destinationSet := convertStringsToTypeSet(destinationSlice)
	err = d.Set("destination_ids", destinationSet)
	if err != nil {
		return fmt.Errorf("error storing 'destination_ids':%s", err)
	}

	appPortProfileSlice := extractIdsFromOpenApiReferences(dfwRule.ApplicationPortProfiles)
	appPortProfileSet := convertStringsToTypeSet(appPortProfileSlice)
	err = d.Set("app_port_profile_ids", appPortProfileSet)
	if err != nil {
		return fmt.Errorf("error storing 'app_port_profile_ids':%s", err)
	}

	netContextProfileSlice := extractIdsFromOpenApiReferences(dfwRule.NetworkContextProfiles)
	netPortProfileSet := convertStringsToTypeSet(netContextProfileSlice)
	err = d.Set("network_context_profile_ids", netPortProfileSet)
	if err != nil {
		return fmt.Errorf("error storing 'network_context_profile_ids':%s", err)
	}

	return nil
}
