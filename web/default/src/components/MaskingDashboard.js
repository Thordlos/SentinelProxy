import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Button,
  Card,
  Header,
  Icon,
  Label,
  Message,
  Segment,
  Statistic,
  Table,
} from 'semantic-ui-react';
import { API, showError } from '../helpers';

const POLL_INTERVAL = 5000;

const MaskingDashboard = () => {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({
    total_sessions: 0,
    total_hits: 0,
    hit_counts: {},
  });
  const [sessions, setSessions] = useState([]);
  const [selectedSession, setSelectedSession] = useState(null);
  const [detail, setDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const loadStats = async () => {
    try {
      const res = await API.get('/api/masking/self/stats');
      const { success, data } = res.data;
      if (success) {
        setStats(data);
      } else {
        showError(t('masking_dashboard.load_stats_failed'));
      }
    } catch (error) {
      console.error('load masking stats failed', error);
    }
  };

  const loadSessions = async () => {
    try {
      const res = await API.get('/api/masking/self/sessions');
      const { success, data } = res.data;
      if (success) {
        setSessions(data || []);
      } else {
        showError(t('masking_dashboard.load_sessions_failed'));
      }
    } catch (error) {
      console.error('load masking sessions failed', error);
    }
  };

  const loadAll = async () => {
    await Promise.all([loadStats(), loadSessions()]);
    setLoading(false);
  };

  const loadDetail = async (sessionId) => {
    setDetailLoading(true);
    setSelectedSession(sessionId);
    try {
      const res = await API.get(`/api/masking/self/sessions/${encodeURIComponent(sessionId)}`);
      const { success, data } = res.data;
      if (success) {
        setDetail(data);
      } else {
        showError(t('masking_dashboard.load_detail_failed'));
      }
    } catch (error) {
      showError(error.message);
    }
    setDetailLoading(false);
  };

  useEffect(() => {
    loadAll();
    const timer = setInterval(loadAll, POLL_INTERVAL);
    return () => clearInterval(timer);
  }, []);

  const formatDate = (value) => {
    if (!value) return '-';
    return new Date(value).toLocaleString();
  };

  const entityTypeColor = (type) => {
    switch (type) {
      case 'PHONE_NUMBER':
        return 'blue';
      case 'ID_CARD':
        return 'red';
      case 'EMAIL_ADDRESS':
        return 'green';
      case 'BANK_CARD':
        return 'purple';
      case 'LICENSE_PLATE':
        return 'orange';
      case 'IP_ADDRESS':
        return 'teal';
      default:
        return 'grey';
    }
  };

  const renderHitCounts = (counts) => {
    const entries = Object.entries(counts || {});
    if (entries.length === 0) {
      return <p style={{ color: '#999' }}>{t('masking_dashboard.no_hits')}</p>;
    }
    return (
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
        {entries.map(([type, count]) => (
          <Label key={type} color={entityTypeColor(type)}>
            {type}
            <Label.Detail>{count}</Label.Detail>
          </Label>
        ))}
      </div>
    );
  };

  return (
    <div className='dashboard-container'>
      <Card fluid className='chart-card'>
        <Card.Content>
          <Card.Header className='header'>{t('masking_dashboard.title')}</Card.Header>

          <Message info>
            {t('masking_dashboard.description')}
          </Message>

          {/* 统计卡片 */}
          <Segment basic loading={loading}>
            <Statistic.Group widths='2' size='small'>
              <Statistic>
                <Statistic.Value>{stats.total_sessions || 0}</Statistic.Value>
                <Statistic.Label>{t('masking_dashboard.total_sessions')}</Statistic.Label>
              </Statistic>
              <Statistic>
                <Statistic.Value>{stats.total_hits || 0}</Statistic.Value>
                <Statistic.Label>{t('masking_dashboard.total_hits')}</Statistic.Label>
              </Statistic>
            </Statistic.Group>
          </Segment>

          {/* 总体命中分布 */}
          <Header as='h3'>{t('masking_dashboard.hit_distribution')}</Header>
          <Segment>
            {renderHitCounts(stats.hit_counts)}
          </Segment>

          {/* 会话列表 */}
          <Header as='h3'>{t('masking_dashboard.sessions')}</Header>
          <Table celled selectable>
            <Table.Header>
              <Table.Row>
                <Table.HeaderCell>{t('masking_dashboard.session_display_id')}</Table.HeaderCell>
                <Table.HeaderCell>{t('masking_dashboard.created_at')}</Table.HeaderCell>
                <Table.HeaderCell>{t('masking_dashboard.last_accessed')}</Table.HeaderCell>
                <Table.HeaderCell>{t('masking_dashboard.entity_count')}</Table.HeaderCell>
                <Table.HeaderCell>{t('masking_dashboard.hit_count')}</Table.HeaderCell>
                <Table.HeaderCell>{t('masking_dashboard.actions')}</Table.HeaderCell>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {sessions.map((session) => (
                <Table.Row
                  key={session.session_id}
                  active={selectedSession === session.session_id}
                >
                  <Table.Cell>
                    <code>{session.display_id}</code>
                  </Table.Cell>
                  <Table.Cell>{formatDate(session.created_at)}</Table.Cell>
                  <Table.Cell>{formatDate(session.last_accessed)}</Table.Cell>
                  <Table.Cell>{session.entity_count || 0}</Table.Cell>
                  <Table.Cell>{session.hit_count || 0}</Table.Cell>
                  <Table.Cell>
                    <Button
                      icon
                      basic
                      color='blue'
                      size='small'
                      onClick={() => loadDetail(session.session_id)}
                      loading={detailLoading && selectedSession === session.session_id}
                    >
                      <Icon name='eye' />
                    </Button>
                  </Table.Cell>
                </Table.Row>
              ))}
              {sessions.length === 0 && (
                <Table.Row>
                  <Table.Cell colSpan='6' textAlign='center'>
                    {t('masking_dashboard.no_sessions')}
                  </Table.Cell>
                </Table.Row>
              )}
            </Table.Body>
          </Table>

          {/* 会话详情 */}
          {detail && (
            <>
              <Header as='h3'>
                {t('masking_dashboard.session_detail')} <code>{detail.display_id}</code>
              </Header>

              <Segment>
                <Header as='h4'>{t('masking_dashboard.hit_distribution')}</Header>
                {renderHitCounts(detail.hit_counts)}
              </Segment>

              {detail.symbol_mappings?.length > 0 && (
                <>
                  <Header as='h4'>{t('masking_dashboard.symbol_mappings')}</Header>
                  <Table celled compact>
                    <Table.Header>
                      <Table.Row>
                        <Table.HeaderCell>{t('masking_dashboard.code')}</Table.HeaderCell>
                        <Table.HeaderCell>{t('masking_dashboard.original')}</Table.HeaderCell>
                        <Table.HeaderCell>{t('masking_dashboard.type')}</Table.HeaderCell>
                      </Table.Row>
                    </Table.Header>
                    <Table.Body>
                      {detail.symbol_mappings.map((m, idx) => (
                        <Table.Row key={idx}>
                          <Table.Cell><code>{m.code}</code></Table.Cell>
                          <Table.Cell>{m.original}</Table.Cell>
                          <Table.Cell>
                            <Label size='small' color={entityTypeColor(m.type)}>
                              {m.type}
                            </Label>
                          </Table.Cell>
                        </Table.Row>
                      ))}
                    </Table.Body>
                  </Table>
                </>
              )}

              {detail.masked_mappings?.length > 0 && (
                <>
                  <Header as='h4'>{t('masking_dashboard.masked_mappings')}</Header>
                  <Table celled compact>
                    <Table.Header>
                      <Table.Row>
                        <Table.HeaderCell>{t('masking_dashboard.masked')}</Table.HeaderCell>
                        <Table.HeaderCell>{t('masking_dashboard.original')}</Table.HeaderCell>
                        <Table.HeaderCell>{t('masking_dashboard.type')}</Table.HeaderCell>
                      </Table.Row>
                    </Table.Header>
                    <Table.Body>
                      {detail.masked_mappings.map((m, idx) => (
                        <Table.Row key={idx}>
                          <Table.Cell><code>{m.masked}</code></Table.Cell>
                          <Table.Cell>{m.original}</Table.Cell>
                          <Table.Cell>
                            <Label size='small' color={entityTypeColor(m.type)}>
                              {m.type}
                            </Label>
                          </Table.Cell>
                        </Table.Row>
                      ))}
                    </Table.Body>
                  </Table>
                </>
              )}

              {detail.ip_mappings?.length > 0 && (
                <>
                  <Header as='h4'>{t('masking_dashboard.ip_mappings')}</Header>
                  <Table celled compact>
                    <Table.Header>
                      <Table.Row>
                        <Table.HeaderCell>{t('masking_dashboard.original')}</Table.HeaderCell>
                        <Table.HeaderCell>{t('masking_dashboard.fake')}</Table.HeaderCell>
                      </Table.Row>
                    </Table.Header>
                    <Table.Body>
                      {detail.ip_mappings.map((m, idx) => (
                        <Table.Row key={idx}>
                          <Table.Cell>{m.original}</Table.Cell>
                          <Table.Cell>{m.fake}</Table.Cell>
                        </Table.Row>
                      ))}
                    </Table.Body>
                  </Table>
                </>
              )}

              {detail.token_mappings?.length > 0 && (
                <>
                  <Header as='h4'>{t('masking_dashboard.token_mappings')}</Header>
                  <Table celled compact>
                    <Table.Header>
                      <Table.Row>
                        <Table.HeaderCell>{t('masking_dashboard.original')}</Table.HeaderCell>
                        <Table.HeaderCell>{t('masking_dashboard.token')}</Table.HeaderCell>
                      </Table.Row>
                    </Table.Header>
                    <Table.Body>
                      {detail.token_mappings.map((m, idx) => (
                        <Table.Row key={idx}>
                          <Table.Cell>{m.original}</Table.Cell>
                          <Table.Cell><code>{m.token}</code></Table.Cell>
                        </Table.Row>
                      ))}
                    </Table.Body>
                  </Table>
                </>
              )}
            </>
          )}
        </Card.Content>
      </Card>
    </div>
  );
};

export default MaskingDashboard;
