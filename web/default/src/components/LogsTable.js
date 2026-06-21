import React, { useEffect, useState } from 'react';
import {
  Button,
  Form,
  Header,
  Icon,
  Label,
  Message,
  Modal,
  Pagination,
  Segment,
  Select,
  Table,
  Popup,
} from 'semantic-ui-react';
import {
  API,
  copy,
  isAdmin,
  showError,
  showSuccess,
  showWarning,
  timestamp2string,
} from '../helpers';
import { useTranslation } from 'react-i18next';

import { ITEMS_PER_PAGE } from '../constants';
import { renderColorLabel, renderQuota } from '../helpers/render';
import { Link } from 'react-router-dom';

const DIFF_COLORS = [
  { bg: '#fff3cd', border: '#ffc107', text: '#856404' },
  { bg: '#d4edda', border: '#28a745', text: '#155724' },
  { bg: '#cce5ff', border: '#007bff', text: '#004085' },
  { bg: '#f8d7da', border: '#dc3545', text: '#721c24' },
  { bg: '#e2e3f3', border: '#6f42c1', text: '#383d41' },
  { bg: '#d1ecf1', border: '#17a2b8', text: '#0c5460' },
  { bg: '#fff8e1', border: '#ff9800', text: '#e65100' },
];

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function tryParseJSON(jsonString) {
  try {
    return JSON.parse(jsonString);
  } catch (e) {
    return null;
  }
}

function extractDiffPairs(original, redacted) {
  const pairs = [];
  const seen = new Set();

  function addSubPairs(a, b) {
    const subPairs = diffStringPair(a, b);
    for (const p of subPairs) {
      const key = `${p.original}\0${p.redacted}`;
      if (seen.has(key)) continue;
      seen.add(key);
      pairs.push(p);
    }
  }

  function walk(a, b) {
    if (typeof a === 'string' && typeof b === 'string') {
      addSubPairs(a, b);
      return;
    }
    if (Array.isArray(a) && Array.isArray(b)) {
      const len = Math.max(a.length, b.length);
      for (let i = 0; i < len; i++) {
        walk(a[i], b[i]);
      }
      return;
    }
    if (a && b && typeof a === 'object' && typeof b === 'object') {
      const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
      for (const key of keys) {
        walk(a[key], b[key]);
      }
      return;
    }
  }

  walk(original, redacted);
  return pairs;
}

function diffStringPair(original, redacted) {
  const pairs = [];
  if (typeof original !== 'string' || typeof redacted !== 'string') return pairs;
  if (original === redacted) return pairs;

  // 把 SENTINEL 标记压缩成单一占位 token，避免被拆分
  const sentinelPlaceholder = {};
  let sentinelIndex = 0;
  const redactedWithPlaceholder = redacted.replace(
    /<SENTINEL>([^\s<>]+)<\/SENTINEL>/g,
    (match, code) => {
      const key = `@@SENTINEL_${sentinelIndex++}@@`;
      sentinelPlaceholder[key] = match;
      return key;
    }
  );

  const tokensA = tokenizeForDiff(original);
  const tokensB = tokenizeForDiff(redactedWithPlaceholder);

  let i = 0;
  let j = 0;
  while (i < tokensA.length || j < tokensB.length) {
    const ta = tokensA[i];
    const tb = tokensB[j];

    if (ta && tb && ta.text === tb.text) {
      i++;
      j++;
      continue;
    }

    // 收集一段差异
    const startA = i;
    const startB = j;
    while (
      i < tokensA.length &&
      j < tokensB.length &&
      tokensA[i].text !== tokensB[j].text
    ) {
      i++;
      j++;
    }

    const originalSegment = tokensA
      .slice(startA, i)
      .map((t) => t.text)
      .join('');
    const redactedSegment = tokensB
      .slice(startB, j)
      .map((t) => t.text)
      .join('');

    // 恢复 SENTINEL 占位符为真实标记
    const restoredRedacted = redactedSegment.replace(
      /@@SENTINEL_(\d+)@@/g,
      (match) => sentinelPlaceholder[match] || match
    );

    if (originalSegment || restoredRedacted) {
      pairs.push({ original: originalSegment, redacted: restoredRedacted });
    }
  }

  return pairs;
}

function tokenizeForDiff(text) {
  const tokens = [];
  let current = '';
  for (const ch of text) {
    if (/[一-龥]/.test(ch)) {
      if (current) {
        tokens.push({ text: current });
        current = '';
      }
      tokens.push({ text: ch });
    } else if (/[a-zA-Z0-9_.@\-]/.test(ch)) {
      current += ch;
    } else {
      if (current) {
        tokens.push({ text: current });
        current = '';
      }
      tokens.push({ text: ch });
    }
  }
  if (current) tokens.push({ text: current });
  return tokens;
}

function buildHighlightMap(pairs) {
  const map = new Map();
  pairs.forEach((pair, index) => {
    const color = DIFF_COLORS[index % DIFF_COLORS.length];
    const baseStyle = {
      backgroundColor: color.bg,
      color: color.text,
      borderRadius: '2px',
      padding: '0 1px',
    };
    map.set(pair.original, {
      baseStyle,
      pair,
      isOriginal: true,
      title: `原始值：${pair.original} → 脱敏值：${pair.redacted}`,
    });
    map.set(pair.redacted, {
      baseStyle,
      pair,
      isOriginal: false,
      title: `脱敏值：${pair.redacted} ← 原始值：${pair.original}`,
    });
  });
  return map;
}

function charDiffLCS(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array(m + 1)
    .fill(null)
    .map(() => Array(n + 1).fill(0));
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }
  const inLCS = Array(m).fill(false);
  let i = m;
  let j = n;
  while (i > 0 && j > 0) {
    if (a[i - 1] === b[j - 1]) {
      inLCS[i - 1] = true;
      i--;
      j--;
    } else if (dp[i - 1][j] >= dp[i][j - 1]) {
      i--;
    } else {
      j--;
    }
  }
  return inLCS;
}

function HighlightedText({ text, highlightMap }) {
  if (!text || !highlightMap || highlightMap.size === 0) {
    return <>{text}</>;
  }

  const patterns = Array.from(highlightMap.keys())
    .filter(Boolean)
    .sort((a, b) => b.length - a.length);
  if (patterns.length === 0) return <>{text}</>;

  const regex = new RegExp(`(${patterns.map(escapeRegExp).join('|')})`, 'g');
  const parts = text.split(regex);

  return (
    <>
      {parts.map((part, idx) => {
        const meta = highlightMap.get(part);
        if (meta) {
          const other = meta.isOriginal ? meta.pair.redacted : meta.pair.original;
          const unchanged = charDiffLCS(part, other);
          return (
            <span key={idx} title={meta.title}>
              {part.split('').map((ch, i) =>
                unchanged[i] ? (
                  <span key={i}>{ch}</span>
                ) : (
                  <span key={i} style={meta.baseStyle}>
                    {ch}
                  </span>
                )
              )}
            </span>
          );
        }
        return <span key={idx}>{part}</span>;
      })}
    </>
  );
}

function renderTimestamp(timestamp, request_id) {
  return (
    <code
      onClick={async () => {
        if (await copy(request_id)) {
          showSuccess(`已复制请求 ID：${request_id}`);
        } else {
          showWarning(`请求 ID 复制失败：${request_id}`);
        }
      }}
      style={{ cursor: 'pointer' }}
    >
      {timestamp2string(timestamp)}
    </code>
  );
}

const MODE_OPTIONS = [
  { key: 'all', text: '全部用户', value: 'all' },
  { key: 'self', text: '当前用户', value: 'self' },
];

function renderType(type) {
  switch (type) {
    case 1:
      return (
        <Label basic color='green'>
          充值
        </Label>
      );
    case 2:
      return (
        <Label basic color='olive'>
          消费
        </Label>
      );
    case 3:
      return (
        <Label basic color='orange'>
          管理
        </Label>
      );
    case 4:
      return (
        <Label basic color='purple'>
          系统
        </Label>
      );
    case 5:
      return (
        <Label basic color='violet'>
          测试
        </Label>
      );
    default:
      return (
        <Label basic color='black'>
          未知
        </Label>
      );
  }
}

function getColorByElapsedTime(elapsedTime) {
  if (elapsedTime === undefined || 0) return 'black';
  if (elapsedTime < 1000) return 'green';
  if (elapsedTime < 3000) return 'olive';
  if (elapsedTime < 5000) return 'yellow';
  if (elapsedTime < 10000) return 'orange';
  return 'red';
}

function renderDetail(log) {
  return (
    <>
      {log.content}
      <br />
      {log.elapsed_time && (
        <Label
          basic
          size={'mini'}
          color={getColorByElapsedTime(log.elapsed_time)}
        >
          {log.elapsed_time} ms
        </Label>
      )}
      {log.is_stream && (
        <>
          <Label size={'mini'} color='pink'>
            Stream
          </Label>
        </>
      )}
      {log.system_prompt_reset && (
        <>
          <Label basic size={'mini'} color='red'>
            System Prompt Reset
          </Label>
        </>
      )}
    </>
  );
}

const LogsTable = () => {
  const { t } = useTranslation();
  const [logs, setLogs] = useState([]);
  const [showStat, setShowStat] = useState(false);
  const [loading, setLoading] = useState(true);
  const [activePage, setActivePage] = useState(1);
  const [searchKeyword, setSearchKeyword] = useState('');
  const [searching, setSearching] = useState(false);
  const [logType, setLogType] = useState(0);
  const [rawLogModalOpen, setRawLogModalOpen] = useState(false);
  const [rawLogLoading, setRawLogLoading] = useState(false);
  const [rawLogData, setRawLogData] = useState(null);
  const [rawLogError, setRawLogError] = useState('');
  const isAdminUser = isAdmin();
  let now = new Date();
  const [inputs, setInputs] = useState({
    username: '',
    token_name: '',
    model_name: '',
    start_timestamp: timestamp2string(0),
    end_timestamp: timestamp2string(now.getTime() / 1000 + 3600),
    channel: '',
  });
  const {
    username,
    token_name,
    model_name,
    start_timestamp,
    end_timestamp,
    channel,
  } = inputs;

  const [stat, setStat] = useState({
    quota: 0,
    token: 0,
  });

  const LOG_OPTIONS = [
    { key: '0', text: t('log.type.all'), value: 0 },
    { key: '1', text: t('log.type.topup'), value: 1 },
    { key: '2', text: t('log.type.usage'), value: 2 },
    { key: '3', text: t('log.type.admin'), value: 3 },
    { key: '4', text: t('log.type.system'), value: 4 },
    { key: '5', text: t('log.type.test'), value: 5 },
  ];

  const handleInputChange = (e, { name, value }) => {
    setInputs((inputs) => ({ ...inputs, [name]: value }));
  };

  const getLogSelfStat = async () => {
    let localStartTimestamp = Date.parse(start_timestamp) / 1000;
    let localEndTimestamp = Date.parse(end_timestamp) / 1000;
    let res = await API.get(
      `/api/log/self/stat?type=${logType}&token_name=${token_name}&model_name=${model_name}&start_timestamp=${localStartTimestamp}&end_timestamp=${localEndTimestamp}`
    );
    const { success, message, data } = res.data;
    if (success) {
      setStat(data);
    } else {
      showError(message);
    }
  };

  const getLogStat = async () => {
    let localStartTimestamp = Date.parse(start_timestamp) / 1000;
    let localEndTimestamp = Date.parse(end_timestamp) / 1000;
    let res = await API.get(
      `/api/log/stat?type=${logType}&username=${username}&token_name=${token_name}&model_name=${model_name}&start_timestamp=${localStartTimestamp}&end_timestamp=${localEndTimestamp}&channel=${channel}`
    );
    const { success, message, data } = res.data;
    if (success) {
      setStat(data);
    } else {
      showError(message);
    }
  };

  const handleEyeClick = async () => {
    if (!showStat) {
      if (isAdminUser) {
        await getLogStat();
      } else {
        await getLogSelfStat();
      }
    }
    setShowStat(!showStat);
  };

  const showUserTokenQuota = () => {
    return logType !== 5;
  };

  const loadLogs = async (startIdx) => {
    let url = '';
    let localStartTimestamp = Date.parse(start_timestamp) / 1000;
    let localEndTimestamp = Date.parse(end_timestamp) / 1000;
    if (isAdminUser) {
      url = `/api/log/?p=${startIdx}&type=${logType}&username=${username}&token_name=${token_name}&model_name=${model_name}&start_timestamp=${localStartTimestamp}&end_timestamp=${localEndTimestamp}&channel=${channel}`;
    } else {
      url = `/api/log/self/?p=${startIdx}&type=${logType}&token_name=${token_name}&model_name=${model_name}&start_timestamp=${localStartTimestamp}&end_timestamp=${localEndTimestamp}`;
    }
    const res = await API.get(url);
    const { success, message, data } = res.data;
    if (success) {
      if (startIdx === 0) {
        setLogs(data);
      } else {
        let newLogs = [...logs];
        newLogs.splice(startIdx * ITEMS_PER_PAGE, data.length, ...data);
        setLogs(newLogs);
      }
    } else {
      showError(message);
    }
    setLoading(false);
  };

  const onPaginationChange = (e, { activePage }) => {
    (async () => {
      if (activePage === Math.ceil(logs.length / ITEMS_PER_PAGE) + 1) {
        // In this case we have to load more data and then append them.
        await loadLogs(activePage - 1);
      }
      setActivePage(activePage);
    })();
  };

  const refresh = async () => {
    setLoading(true);
    setActivePage(1);
    await loadLogs(0);
  };

  const loadRawLog = async (logId) => {
    setRawLogLoading(true);
    setRawLogError('');
    setRawLogData(null);
    try {
      const res = await API.get(`/api/log/${logId}/raw`);
      const { success, message, data } = res.data;
      if (success) {
        setRawLogData(data);
      } else {
        setRawLogError(message || '加载原始日志失败');
      }
    } catch (error) {
      setRawLogError(error.message || '加载原始日志失败');
    }
    setRawLogLoading(false);
  };

  const openRawLogModal = (logId) => {
    setRawLogModalOpen(true);
    loadRawLog(logId);
  };

  const closeRawLogModal = () => {
    setRawLogModalOpen(false);
    setRawLogData(null);
    setRawLogError('');
  };

  useEffect(() => {
    refresh().then();
  }, [logType]);

  const searchLogs = async () => {
    if (searchKeyword === '') {
      // if keyword is blank, load files instead.
      await loadLogs(0);
      setActivePage(1);
      return;
    }
    setSearching(true);
    const res = await API.get(`/api/log/self/search?keyword=${searchKeyword}`);
    const { success, message, data } = res.data;
    if (success) {
      setLogs(data);
      setActivePage(1);
    } else {
      showError(message);
    }
    setSearching(false);
  };

  const handleKeywordChange = async (e, { value }) => {
    setSearchKeyword(value.trim());
  };

  const sortLog = (key) => {
    if (logs.length === 0) return;
    setLoading(true);
    let sortedLogs = [...logs];
    if (typeof sortedLogs[0][key] === 'string') {
      sortedLogs.sort((a, b) => {
        return ('' + a[key]).localeCompare(b[key]);
      });
    } else {
      sortedLogs.sort((a, b) => {
        if (a[key] === b[key]) return 0;
        if (a[key] > b[key]) return -1;
        if (a[key] < b[key]) return 1;
      });
    }
    if (sortedLogs[0].id === logs[0].id) {
      sortedLogs.reverse();
    }
    setLogs(sortedLogs);
    setLoading(false);
  };

  return (
    <>
      <Header as='h3'>
        {t('log.usage_details')}（{t('log.total_quota')}：
        {showStat && renderQuota(stat.quota, t)}
        {!showStat && (
          <span
            onClick={handleEyeClick}
            style={{ cursor: 'pointer', color: 'gray' }}
          >
            {t('log.click_to_view')}
          </span>
        )}
        ）
      </Header>
      <Form>
        <Form.Group>
          <Form.Input
            fluid
            label={t('log.table.token_name')}
            size={'small'}
            width={3}
            value={token_name}
            placeholder={t('log.table.token_name_placeholder')}
            name='token_name'
            onChange={handleInputChange}
          />
          <Form.Input
            fluid
            label={t('log.table.model_name')}
            size={'small'}
            width={3}
            value={model_name}
            placeholder={t('log.table.model_name_placeholder')}
            name='model_name'
            onChange={handleInputChange}
          />
          <Form.Input
            fluid
            label={t('log.table.start_time')}
            size={'small'}
            width={4}
            value={start_timestamp}
            type='datetime-local'
            name='start_timestamp'
            onChange={handleInputChange}
          />
          <Form.Input
            fluid
            label={t('log.table.end_time')}
            size={'small'}
            width={4}
            value={end_timestamp}
            type='datetime-local'
            name='end_timestamp'
            onChange={handleInputChange}
          />
          <Form.Button
            fluid
            label={t('log.buttons.query')}
            size={'small'}
            width={2}
            onClick={refresh}
          >
            {t('log.buttons.submit')}
          </Form.Button>
        </Form.Group>
        {isAdminUser && (
          <>
            <Form.Group>
              <Form.Input
                fluid
                label={t('log.table.channel_id')}
                size={'small'}
                width={3}
                value={channel}
                placeholder={t('log.table.channel_id_placeholder')}
                name='channel'
                onChange={handleInputChange}
              />
              <Form.Input
                fluid
                label={t('log.table.username')}
                size={'small'}
                width={3}
                value={username}
                placeholder={t('log.table.username_placeholder')}
                name='username'
                onChange={handleInputChange}
              />
            </Form.Group>
          </>
        )}
        <Form.Input
          icon='search'
          placeholder={t('log.search')}
          value={searchKeyword}
          onChange={(e, { value }) => setSearchKeyword(value)}
        />
      </Form>
      <Table basic={'very'} compact size='small'>
        <Table.Header>
          <Table.Row>
            <Table.HeaderCell
              style={{ cursor: 'pointer' }}
              onClick={() => {
                sortLog('created_time');
              }}
              width={3}
            >
              {t('log.table.time')}
            </Table.HeaderCell>
            {isAdminUser && (
              <Table.HeaderCell
                style={{ cursor: 'pointer' }}
                onClick={() => {
                  sortLog('channel');
                }}
                width={1}
              >
                {t('log.table.channel')}
              </Table.HeaderCell>
            )}
            <Table.HeaderCell
              style={{ cursor: 'pointer' }}
              onClick={() => {
                sortLog('type');
              }}
              width={1}
            >
              {t('log.table.type')}
            </Table.HeaderCell>
            <Table.HeaderCell
              style={{ cursor: 'pointer' }}
              onClick={() => {
                sortLog('model_name');
              }}
              width={2}
            >
              {t('log.table.model')}
            </Table.HeaderCell>
            {showUserTokenQuota() && (
              <>
                {isAdminUser && (
                  <Table.HeaderCell
                    style={{ cursor: 'pointer' }}
                    onClick={() => {
                      sortLog('username');
                    }}
                    width={2}
                  >
                    {t('log.table.username')}
                  </Table.HeaderCell>
                )}
                <Table.HeaderCell
                  style={{ cursor: 'pointer' }}
                  onClick={() => {
                    sortLog('token_name');
                  }}
                  width={2}
                >
                  {t('log.table.token_name')}
                </Table.HeaderCell>
                <Table.HeaderCell
                  style={{ cursor: 'pointer' }}
                  onClick={() => {
                    sortLog('prompt_tokens');
                  }}
                  width={1}
                >
                  {t('log.table.prompt_tokens')}
                </Table.HeaderCell>
                <Table.HeaderCell
                  style={{ cursor: 'pointer' }}
                  onClick={() => {
                    sortLog('completion_tokens');
                  }}
                  width={1}
                >
                  {t('log.table.completion_tokens')}
                </Table.HeaderCell>
                <Table.HeaderCell
                  style={{ cursor: 'pointer' }}
                  onClick={() => {
                    sortLog('quota');
                  }}
                  width={1}
                >
                  {t('log.table.quota')}
                </Table.HeaderCell>
              </>
            )}
            <Table.HeaderCell width={1}>原始日志</Table.HeaderCell>
            <Table.HeaderCell>{t('log.table.detail')}</Table.HeaderCell>
          </Table.Row>
        </Table.Header>

        <Table.Body>
          {logs
            .slice(
              (activePage - 1) * ITEMS_PER_PAGE,
              activePage * ITEMS_PER_PAGE
            )
            .map((log, idx) => {
              if (log.deleted) return <></>;
              return (
                <Table.Row key={log.id}>
                  <Table.Cell>
                    {renderTimestamp(log.created_at, log.request_id)}
                  </Table.Cell>
                  {isAdminUser && (
                    <Table.Cell>
                      {log.channel ? (
                        <Label
                          basic
                          as={Link}
                          to={`/channel/edit/${log.channel}`}
                        >
                          {log.channel}
                        </Label>
                      ) : (
                        ''
                      )}
                    </Table.Cell>
                  )}
                  <Table.Cell>{renderType(log.type)}</Table.Cell>
                  <Table.Cell>
                    {log.model_name ? renderColorLabel(log.model_name) : ''}
                  </Table.Cell>
                  {showUserTokenQuota() && (
                    <>
                      {isAdminUser && (
                        <Table.Cell>
                          {log.username ? (
                            <Label
                              basic
                              as={Link}
                              to={`/user/edit/${log.user_id}`}
                            >
                              {log.username}
                            </Label>
                          ) : (
                            ''
                          )}
                        </Table.Cell>
                      )}
                      <Table.Cell>
                        {log.token_name ? renderColorLabel(log.token_name) : ''}
                      </Table.Cell>

                      <Table.Cell>
                        {log.prompt_tokens ? log.prompt_tokens : ''}
                      </Table.Cell>
                      <Table.Cell>
                        {log.completion_tokens ? log.completion_tokens : ''}
                      </Table.Cell>
                      <Table.Cell>
                        {log.quota ? renderQuota(log.quota, t, 6) : ''}
                      </Table.Cell>
                    </>
                  )}

                  <Table.Cell>
                    <Button
                      icon
                      basic
                      size='small'
                      title='查看原始请求/响应'
                      onClick={() => openRawLogModal(log.id)}
                    >
                      <Icon name='eye' />
                    </Button>
                  </Table.Cell>

                  <Table.Cell>{renderDetail(log)}</Table.Cell>
                </Table.Row>
              );
            })}
        </Table.Body>

        <Table.Footer>
          <Table.Row>
            <Table.HeaderCell colSpan={'11'}>
              <Select
                placeholder={t('log.type.select')}
                options={LOG_OPTIONS}
                style={{ marginRight: '8px' }}
                name='logType'
                value={logType}
                onChange={(e, { name, value }) => {
                  setLogType(value);
                }}
              />
              <Button size='small' onClick={refresh} loading={loading}>
                {t('log.buttons.refresh')}
              </Button>
              <Pagination
                floated='right'
                activePage={activePage}
                onPageChange={onPaginationChange}
                size='small'
                siblingRange={1}
                totalPages={
                  Math.ceil(logs.length / ITEMS_PER_PAGE) +
                  (logs.length % ITEMS_PER_PAGE === 0 ? 1 : 0)
                }
              />
            </Table.HeaderCell>
          </Table.Row>
        </Table.Footer>
      </Table>

      <Modal
        open={rawLogModalOpen}
        onClose={closeRawLogModal}
        size='large'
        closeIcon
      >
        <Modal.Header>原始请求/响应详情</Modal.Header>
        <Modal.Content scrolling>
          {rawLogLoading && <Segment loading>加载中...</Segment>}
          {!rawLogLoading && rawLogError && (
            <Message negative>{rawLogError}</Message>
          )}
          {!rawLogLoading && rawLogData && (
            <>
              {rawLogData.request && (
                <>
                  <Header as='h4'>原始请求（脱敏前）</Header>
                  <Segment>
                    <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                      <HighlightedText
                        text={rawLogData.request}
                        highlightMap={buildHighlightMap(
                          extractDiffPairs(
                            tryParseJSON(rawLogData.request),
                            tryParseJSON(rawLogData.request_after_redaction)
                          )
                        )}
                      />
                    </pre>
                  </Segment>
                </>
              )}
              {rawLogData.request_after_redaction && (
                <>
                  <Header as='h4'>脱敏后请求</Header>
                  <Segment>
                    <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                      <HighlightedText
                        text={rawLogData.request_after_redaction}
                        highlightMap={buildHighlightMap(
                          extractDiffPairs(
                            tryParseJSON(rawLogData.request),
                            tryParseJSON(rawLogData.request_after_redaction)
                          )
                        )}
                      />
                    </pre>
                  </Segment>
                </>
              )}
              {rawLogData.request_converted && (
                <>
                  <Header as='h4'>转换后请求（发给上游）</Header>
                  <Segment>
                    <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                      <HighlightedText
                        text={rawLogData.request_converted}
                        highlightMap={buildHighlightMap(
                          extractDiffPairs(
                            tryParseJSON(rawLogData.request),
                            tryParseJSON(rawLogData.request_after_redaction)
                          )
                        )}
                      />
                    </pre>
                  </Segment>
                </>
              )}
              {rawLogData.response_from_upstream && (
                <>
                  <Header as='h4'>上游原始响应</Header>
                  <Segment>
                    <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                      <HighlightedText
                        text={rawLogData.response_from_upstream}
                        highlightMap={buildHighlightMap(
                          extractDiffPairs(
                            tryParseJSON(rawLogData.response_from_upstream),
                            tryParseJSON(rawLogData.response)
                          )
                        )}
                      />
                    </pre>
                  </Segment>
                </>
              )}
              {rawLogData.response && (
                <>
                  <Header as='h4'>最终响应（还原后）</Header>
                  <Segment>
                    <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                      <HighlightedText
                        text={rawLogData.response}
                        highlightMap={buildHighlightMap(
                          extractDiffPairs(
                            tryParseJSON(rawLogData.response_from_upstream),
                            tryParseJSON(rawLogData.response)
                          )
                        )}
                      />
                    </pre>
                  </Segment>
                </>
              )}
              {rawLogData.stream_text && (
                <>
                  <Header as='h4'>流式响应文本</Header>
                  <Segment>
                    <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                      <HighlightedText
                        text={rawLogData.stream_text}
                        highlightMap={buildHighlightMap(
                          extractDiffPairs(
                            tryParseJSON(rawLogData.request),
                            tryParseJSON(rawLogData.request_after_redaction)
                          )
                        )}
                      />
                    </pre>
                  </Segment>
                </>
              )}
              {!rawLogData.request &&
                !rawLogData.request_after_redaction &&
                !rawLogData.request_converted &&
                !rawLogData.response_from_upstream &&
                !rawLogData.response &&
                !rawLogData.stream_text && (
                  <Message info>未找到原始请求/响应记录。请确认已开启「记录原始请求/响应」开关。</Message>
                )}
            </>
          )}
        </Modal.Content>
        <Modal.Actions>
          <Button onClick={closeRawLogModal}>关闭</Button>
        </Modal.Actions>
      </Modal>
    </>
  );
};

export default LogsTable;
