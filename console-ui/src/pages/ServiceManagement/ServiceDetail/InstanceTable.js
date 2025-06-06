/*
 * Copyright 1999-2018 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import React from 'react';
import PropTypes from 'prop-types';
import { getParams, request } from '../../../globalLib';
import { Button, ConfigProvider, Message, Pagination, Table } from '@alifd/next';
import { HEALTHY_COLOR_MAPPING } from './constant';
import EditInstanceDialog from './EditInstanceDialog';
import { isDiff } from './util';
import { GLOBAL_PAGE_SIZE_LIST } from '../../../constants';

@ConfigProvider.config
class InstanceTable extends React.Component {
  static displayName = 'InstanceTable';

  static propTypes = {
    locale: PropTypes.object,
    clusterName: PropTypes.string,
    serviceName: PropTypes.string,
    groupName: PropTypes.string,
    filters: PropTypes.object,
  };

  static defaultProps = {
    filters: new Map(),
  };

  constructor(props) {
    super(props);
    this.editInstanceDialog = React.createRef();
    this.state = {
      loading: false,
      instance: { count: 0, list: [] },
      // tableData: {},
      pageNum: 1,
      pageSize: 10,
    };
  }

  componentDidMount() {
    this.getInstanceList();
  }

  openLoading() {
    this.setState({ loading: true });
  }

  closeLoading() {
    this.setState({ loading: false });
  }

  getInstanceList() {
    const { clusterName, serviceName, groupName, filters } = this.props;

    if (!clusterName) return;
    const { pageSize, pageNum } = this.state;
    const namespaceId = getParams('namespaceId');
    const url =
      namespaceId === null
        ? 'v3/console/ns/instance/list'
        : `v3/console/ns/instance/list?namespaceId=${namespaceId}`;
    request({
      url,
      data: {
        serviceName,
        clusterName,
        groupName,
        pageSize,
        pageNo: pageNum,
      },
      beforeSend: () => this.openLoading(),
      success: ({ data }) => {
        const instance = {
          list: data.pageItems || [],
          count: data.totalCount || 0,
        };
        this.setState({ instance });
      },
      error: e => Message.error(e.responseText || 'error'),
      complete: () => this.closeLoading(),
    });
  }

  openInstanceDialog(instance) {
    this.editInstanceDialog.current.getInstance().show(instance);
  }

  switchState(index, record) {
    const { instance } = this.state;
    const { ip, port, ephemeral, weight, enabled, metadata } = record;
    const { clusterName, serviceName, groupName } = this.props;
    request({
      method: 'PUT',
      url: 'v3/console/ns/instance',
      data: {
        serviceName,
        clusterName,
        groupName,
        ip,
        port,
        ephemeral,
        weight,
        enabled: !enabled,
        metadata: JSON.stringify(metadata),
      },
      dataType: 'json',
      beforeSend: () => this.openLoading(),
      success: ({ data }) => {
        const newVal = Object.assign({}, instance);
        newVal.list[index].enabled = !enabled;
        this.setState({ instance: newVal });
      },
      error: e => Message.error(e.responseText || 'error'),
      complete: () => this.closeLoading(),
    });
  }

  handlePageSizeChange(pageSize) {
    this.setState({ pageSize }, () => this.getInstanceList());
  }

  onChangePage(pageNum) {
    this.setState({ pageNum }, () => this.getInstanceList());
  }

  rowColor = ({ healthy }) => ({ className: `row-bg-${HEALTHY_COLOR_MAPPING[`${healthy}`]}` });

  render() {
    const { locale = {} } = this.props;
    const { clusterName, serviceName, groupName } = this.props;
    const { instance, pageSize, loading } = this.state;
    const instanceList = instanceFilter(instance.list, this.props.filters);

    const _instance = {
      count: instanceList.length,
      list: instanceList,
    };

    return _instance.count ? (
      <div>
        <Table dataSource={_instance.list} loading={loading} rowProps={this.rowColor}>
          <Table.Column width={138} title="IP" dataIndex="ip" />
          <Table.Column width={100} title={locale.port} dataIndex="port" />
          <Table.Column
            width={100}
            title={locale.ephemeral}
            dataIndex="ephemeral"
            cell={val => `${val}`}
          />
          <Table.Column width={100} title={locale.weight} dataIndex="weight" />
          <Table.Column
            width={100}
            title={locale.healthy}
            dataIndex="healthy"
            cell={val => `${val}`}
          />
          <Table.Column
            title={locale.metadata}
            dataIndex="metadata"
            cell={(metadata = {}) => {
              if (!metadata) return null;
              return Object.keys(metadata).map(k => (
                <p key={k}>
                  {k}={metadata[k]}
                </p>
              ));
            }}
          />
          <Table.Column
            title={locale.operation}
            width={160}
            cell={(value, index, record) => (
              <div>
                <Button
                  type="normal"
                  className="edit-btn"
                  onClick={() => this.openInstanceDialog(record)}
                >
                  {locale.editor}
                </Button>
                <Button
                  type={record.enabled ? 'normal' : 'secondary'}
                  onClick={() => this.switchState(index, record)}
                >
                  {locale[record.enabled ? 'offline' : 'online']}
                </Button>
              </div>
            )}
          />
        </Table>
        {instance.count > 10 ? (
          <Pagination
            className="pagination"
            total={instance.count}
            pageSize={this.state.pageSize}
            current={this.state.pageNum}
            pageSizeList={GLOBAL_PAGE_SIZE_LIST}
            pageSizePosition="start"
            pageSizeSelector="dropdown"
            popupProps={{ align: 'bl tl' }}
            onPageSizeChange={pageSize => this.handlePageSizeChange(pageSize)}
            onChange={currentPage => this.onChangePage(currentPage)}
          />
        ) : null}
        <EditInstanceDialog
          ref={this.editInstanceDialog}
          serviceName={serviceName}
          clusterName={clusterName}
          groupName={groupName}
          openLoading={() => this.openLoading()}
          closeLoading={() => this.closeLoading()}
          getInstanceList={() => this.getInstanceList()}
        />
      </div>
    ) : null;
  }
}

const instanceFilter = function(array, filters) {
  return array.filter(item => {
    const { metadata } = item;
    let isTargetInstance = true;

    filters.forEach((value, key) => {
      if (value !== metadata[key]) {
        isTargetInstance = false;
        return isTargetInstance;
      }
    });

    return isTargetInstance;
  });
};

export default InstanceTable;
