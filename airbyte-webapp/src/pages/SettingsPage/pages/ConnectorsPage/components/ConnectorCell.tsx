import React from "react";

import { ReleaseStageBadge } from "components/ReleaseStageBadge";
import { FlexContainer } from "components/ui/Flex";

import { SvgIcon } from "area/connector/utils";
import { ReleaseStage } from "core/request/AirbyteClient";
import { FeatureItem, useFeature } from "core/services/features";

import styles from "./ConnectorCell.module.scss";
import { ConnectorsViewProps } from "./ConnectorsView";
import { DestinationUpdateIndicator } from "./DestinationUpdateIndicator";
import { SourceUpdateIndicator } from "./SourceUpdateIndicator";

export interface ConnectorCellProps {
  connectorName: string;
  img?: string;
  releaseStage?: ReleaseStage;
  currentVersion: string;
  type: ConnectorsViewProps["type"];
  id: string;
}

const ConnectorCell: React.FC<ConnectorCellProps> = React.memo(
  ({ connectorName, img, releaseStage, type, id, currentVersion }) => {
    const allowUpdateConnectors = useFeature(FeatureItem.AllowUpdateConnectors);

    return (
      <FlexContainer alignItems="center" gap="lg">
        {allowUpdateConnectors && type === "sources" && (
          <SourceUpdateIndicator id={id} currentVersion={currentVersion} releaseStage={releaseStage} />
        )}
        {allowUpdateConnectors && type === "destinations" && (
          <DestinationUpdateIndicator id={id} currentVersion={currentVersion} />
        )}
        <div className={styles.iconContainer}>
          <SvgIcon svg={img} />
        </div>
        <div>{connectorName}</div>
        <ReleaseStageBadge small tooltip={false} stage={releaseStage} />
      </FlexContainer>
    );
  }
);
ConnectorCell.displayName = "ConnectorCell";

export default ConnectorCell;
