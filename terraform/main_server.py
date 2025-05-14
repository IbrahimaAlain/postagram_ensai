#!/usr/bin/env python
from constructs import Construct
from cdktf import App, TerraformStack
from cdktf_cdktf_provider_aws.provider import AwsProvider
from cdktf_cdktf_provider_aws.default_vpc import DefaultVpc
from cdktf_cdktf_provider_aws.default_subnet import DefaultSubnet
from cdktf_cdktf_provider_aws.launch_template import LaunchTemplate
from cdktf_cdktf_provider_aws.lb import Lb
from cdktf_cdktf_provider_aws.lb_target_group import LbTargetGroup
from cdktf_cdktf_provider_aws.lb_listener import LbListener, LbListenerDefaultAction
from cdktf_cdktf_provider_aws.autoscaling_group import AutoscalingGroup
from cdktf_cdktf_provider_aws.security_group import SecurityGroup, SecurityGroupIngress, SecurityGroupEgress
from cdktf_cdktf_provider_aws.data_aws_caller_identity import DataAwsCallerIdentity

import base64

# Mettez ici le nom du bucket S3 crée dans la partie serverless
bucket="my_bucket20250423140830095600000001"

# Mettez ici le nom de la table dynamoDB créée dans la partie serverless
dynamo_table="my_table_dynamo"

# Mettez ici l'url de votre dépôt github. Votre dépôt doit être public !!!
your_repo="https://github.com/IbrahimaAlain/postagram_ensai.git"

# Le user data pour lancer votre websservice. Il fonctionne tel quel
user_data= base64.b64encode(f"""#!/bin/bash
echo "userdata-start"        
apt update
apt install -y python3-pip python3.12-venv
git clone {your_repo} projet
cd projet/webservice
python3 -m venv venv
source venv/bin/activate
rm .env
echo 'BUCKET={bucket}' >> .env
echo 'DYNAMO_TABLE={dynamo_table}' >> .env
pip3 install -r requirements.txt
venv/bin/python app.py
echo "userdata-end""".encode("ascii")).decode("ascii")


class ServerStack(TerraformStack):
    
    def __init__(self, scope: Construct, id: str):
        super().__init__(scope, id)

        # account_id = l'id de votre compte
        # security_group = le security groupe pour vos instances EC2
        account_id, security_group, subnets, default_vpc = self.infra_base()
        
        launch_template = LaunchTemplate(
            self, "launch template",
            image_id=""
            instance_type="t2.micro", # le type de l'instance
            vpc_security_group_ids = [security_group.id],
            key_name="vockey",
            user_data=user_data,
            tags={"Name":"TP noté"},
            iam_instance_profile={"name":"LabInstanceProfile"}
            )
    

        lb = Lb(
            self, "lb",
            load_balancer_type="application",
            security_groups=[security_group.id],
            subnets=subnets
        )

        target_group=LbTargetGroup(
            self, "tg_group",
            port=8080,
            protocol="HTTP",
            vpc_id=default_vpc.id,
            target_type="instance",
            health_check={
                "enabled": True,
                "path": "/docs",
                "port": "8080",
                "protocol": "HTTP",
                "interval": 30,
                "timeout": 5,
                "unhealthy_threshold": 2,
                "matcher": "200-399" 
            }
        )

        lb_listener = LbListener(
            self, "lb_listener",
            load_balancer_arn=lb.arn,
            port=80,
            protocol="HTTP",
            default_action=[LbListenerDefaultAction(type="forward", target_group_arn=target_group.arn)]
        )

        asg = AutoscalingGroup(
            self, "asg",
            min_size=1,
            max_size=4,
            desired_capacity=1,
            launch_template={"id": launch_template.id},
            vpc_zone_identifier=subnets,
            target_group_arns=[target_group.arn]
        )

    def infra_base(self):
        """
        Permet de définir une infra de base, vous ne devez pas y toucher !
        """
        AwsProvider(self, "AWS", region="us-east-1")
        account_id = DataAwsCallerIdentity(self, "acount_id").account_id

        default_vpc = DefaultVpc(
            self, "default_vpc"
        )
            
        # Les AZ de us-east-1 sont de la forme us-east-1x 
        # avec x une lettre dans abcdef. Ne permet pas de déployer
        # automatiquement ce code sur une autre région. Le code
        # pour y arriver est vraiment compliqué.
        az_ids = [f"us-east-1{i}" for i in "abcdef"]
        subnets= []
        for i,az_id in enumerate(az_ids):
            subnets.append(DefaultSubnet(
            self, f"default_sub{i}",
            availability_zone=az_id
        ).id)
            

        security_group = SecurityGroup(
            self, "sg-tp",
            ingress=[
                SecurityGroupIngress(
                    from_port=22,
                    to_port=22,
                    cidr_blocks=["0.0.0.0/0"],
                    protocol="TCP",
                ),
                SecurityGroupIngress(
                    from_port=80,
                    to_port=80,
                    cidr_blocks=["0.0.0.0/0"],
                    protocol="TCP"
                ),
                SecurityGroupIngress(
                    from_port=8080,
                    to_port=8080,
                    cidr_blocks=["0.0.0.0/0"],
                    protocol="TCP"
                )
            ],
            egress=[
                SecurityGroupEgress(
                    from_port=0,
                    to_port=0,
                    cidr_blocks=["0.0.0.0/0"],
                    protocol="-1"
                )
            ]
            )
        return account_id, security_group, subnets, default_vpc

app = App()
ServerStack(app, "cdktf_server")
app.synth()
