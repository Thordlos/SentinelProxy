import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Button,
  Card,
  Checkbox,
  Dropdown,
  Form,
  Header,
  Icon,
  Input,
  Message,
  Segment,
  Table,
  TextArea,
} from 'semantic-ui-react';
import { API, showError, showSuccess } from '../helpers';

const operatorOptions = [
  { key: 'symbolize', text: '可恢复 — 符号化（替换为代号）', value: 'symbolize', description: '可恢复' },
  { key: 'mask', text: '可恢复 — 掩码化（部分掩码）', value: 'mask', description: '可恢复' },
  { key: 'randomize', text: '可恢复 — 格式保持随机化', value: 'randomize', description: '可恢复' },
  { key: 'tokenize', text: '可恢复 — 定长 Token 化', value: 'tokenize', description: '可恢复' },
  { key: 'block', text: '阻断 — 阻断请求', value: 'block', description: '阻断' },
];

// 将旧操作符名称映射为新名称（向后兼容）
const normalizeOperatorType = (type) => {
  const aliasMap = {
    replace: 'symbolize',
    ip_random: 'randomize',
  };
  return aliasMap[type] || type || 'symbolize';
};

const codeStyleOptions = [
  { key: 'typed', text: '类型编号（如 PHONE_NUMBER_1）', value: 'typed' },
  { key: 'RAND', text: '随机字符串（如 ENT_a3f9k2）', value: 'RAND' },
];

const defaultOperatorConfig = (type) => {
  const normalized = normalizeOperatorType(type);
  switch (normalized) {
    case 'mask':
      return { type: 'mask', mask_char: '*', chars_to_mask: 4, from_end: false };
    case 'block':
      return { type: 'block' };
    case 'randomize':
      return { type: 'randomize', ip_random_preserve_scope: true, ip_random_cross_class: true, ip_random_preserve_bits: 0 };
    case 'tokenize':
      return { type: 'tokenize', token_length: 16, token_chars: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' };
    case 'symbolize':
    default:
      return { type: 'symbolize' };
  }
};

const MaskingSetting = () => {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [config, setConfig] = useState({
    enabled: true,
    fail_closed: true,
    score_threshold: 0.0,
    max_text_length: 1048576,
    cache_ttl_hours: 24,
    state_dir: 'logs/masking',
    code_style: 'typed',
    code_prefix: 'ENT',
    code_length: 6,
    log_raw_requests: false,
    default_operator: { type: 'symbolize' },
    built_in_entities: [],
    static_rules: [],
    dynamic_rules: [],
  });
  const [builtinEntities, setBuiltinEntities] = useState([]);

  // Preview states
  const [previewText, setPreviewText] = useState('');
  const [previewSession, setPreviewSession] = useState('');
  const [previewResult, setPreviewResult] = useState(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  useEffect(() => {
    loadConfig();
    loadBuiltinEntities();
    // Generate a preview session ID
    setPreviewSession('preview_' + Date.now());
  }, []);

  const loadConfig = async () => {
    setLoading(true);
    try {
      const res = await API.get('/api/masking/config');
      const { success, data } = res.data;
      if (success) {
        setConfig(data);
      } else {
        showError('加载配置失败');
      }
    } catch (error) {
      showError(error.message);
    }
    setLoading(false);
  };

  const loadBuiltinEntities = async () => {
    try {
      const res = await API.get('/api/masking/builtin');
      const { success, data } = res.data;
      if (success) {
        setBuiltinEntities(data || []);
      }
    } catch (error) {
      console.error('加载内置实体失败', error);
    }
  };

  const saveConfig = async () => {
    setSaving(true);
    try {
      const res = await API.post('/api/masking/config', config);
      const { success, message } = res.data;
      if (success) {
        showSuccess(message || '配置已保存并生效');
      } else {
        showError(message || '保存失败');
      }
    } catch (error) {
      showError(error.message);
    }
    setSaving(false);
  };

  const updateConfig = (field, value) => {
    setConfig((prev) => ({ ...prev, [field]: value }));
  };

  const updateBuiltInEntity = (idx, field, value) => {
    const newEntities = [...config.built_in_entities];
    newEntities[idx] = { ...newEntities[idx], [field]: value };
    setConfig((prev) => ({ ...prev, built_in_entities: newEntities }));
  };

  const updateBuiltInOperator = (idx, operatorType) => {
    const newEntities = [...config.built_in_entities];
    newEntities[idx] = {
      ...newEntities[idx],
      operator: defaultOperatorConfig(operatorType),
    };
    setConfig((prev) => ({ ...prev, built_in_entities: newEntities }));
  };

  const updateBuiltInOperatorConfig = (idx, operatorUpdates) => {
    const newEntities = [...config.built_in_entities];
    newEntities[idx] = {
      ...newEntities[idx],
      operator: { ...newEntities[idx].operator, ...operatorUpdates },
    };
    setConfig((prev) => ({ ...prev, built_in_entities: newEntities }));
  };

  const addRule = (type) => {
    const newRule = {
      id: '',
      name: '',
      entity_type: '',
      operator: { type: 'symbolize' },
      score: 1.0,
    };
    if (type === 'static') {
      newRule.keyword = '';
    } else {
      newRule.pattern = '';
    }
    setConfig((prev) => ({
      ...prev,
      [type === 'static' ? 'static_rules' : 'dynamic_rules']: [
        ...prev[type === 'static' ? 'static_rules' : 'dynamic_rules'],
        newRule,
      ],
    }));
  };

  const updateRule = (type, idx, field, value) => {
    const key = type === 'static' ? 'static_rules' : 'dynamic_rules';
    const newRules = [...config[key]];
    newRules[idx] = { ...newRules[idx], [field]: value };
    setConfig((prev) => ({ ...prev, [key]: newRules }));
  };

  const updateRuleOperator = (type, idx, operatorType) => {
    const key = type === 'static' ? 'static_rules' : 'dynamic_rules';
    const newRules = [...config[key]];
    newRules[idx] = { ...newRules[idx], operator: defaultOperatorConfig(operatorType) };
    setConfig((prev) => ({ ...prev, [key]: newRules }));
  };

  const removeRule = (type, idx) => {
    const key = type === 'static' ? 'static_rules' : 'dynamic_rules';
    const newRules = [...config[key]];
    newRules.splice(idx, 1);
    setConfig((prev) => ({ ...prev, [key]: newRules }));
  };

  const generateUniqueRuleId = (baseId) => {
    const existingIds = new Set([
      ...config.static_rules.map((r) => r.id),
      ...config.dynamic_rules.map((r) => r.id),
    ]);
    let candidateId = baseId;
    let suffix = 1;
    while (existingIds.has(candidateId)) {
      candidateId = `${baseId}_${suffix}`;
      suffix++;
    }
    return candidateId;
  };

  const copyBuiltinToDynamic = (entity) => {
    const builtin = builtinEntities.find((e) => e.type === entity.type);
    const pattern = builtin?.pattern || '';

    if (!pattern) {
      showError(`内置规则 "${entity.name}" 暂无正则表达式，无法复制`);
      return;
    }

    const baseId = entity.type.toLowerCase();
    const newId = generateUniqueRuleId(baseId);

    const newRule = {
      id: newId,
      name: `${entity.name}（自定义）`,
      entity_type: entity.type,
      pattern: pattern,
      score: 1.0,
      operator: { ...entity.operator },
      description: `从内置规则 "${entity.name}" 复制`,
    };

    setConfig((prev) => ({
      ...prev,
      dynamic_rules: [...prev.dynamic_rules, newRule],
    }));

    showSuccess(`已复制 "${entity.name}" 到自定义正则规则，请点击保存生效`);
  };

  const runPreview = async () => {
    if (!previewText) return;
    setPreviewLoading(true);
    try {
      const res = await API.post('/api/masking/preview', {
        text: previewText,
        session_id: previewSession,
      });
      const { success, data } = res.data;
      if (success) {
        setPreviewResult(data);
      } else {
        showError('预览失败');
      }
    } catch (error) {
      showError(error.message);
    }
    setPreviewLoading(false);
  };

  const renderOperatorConfig = (operator, onChange) => {
    switch (operator.type) {
      case 'mask':
        return (
          <>
            <Form.Field
              control={Input}
              label='掩码字符'
              value={operator.mask_char || '*'}
              onChange={(e) => onChange({ ...operator, mask_char: e.target.value })}
              style={{ width: '80px' }}
            />
            <Form.Field
              control={Input}
              label='掩码位数'
              type='number'
              value={operator.chars_to_mask || 4}
              onChange={(e) => onChange({ ...operator, chars_to_mask: parseInt(e.target.value) || 0 })}
              style={{ width: '100px' }}
            />
            <Form.Field
              control={Checkbox}
              label='从末尾开始'
              checked={operator.from_end || false}
              onChange={(e, { checked }) => onChange({ ...operator, from_end: checked })}
            />
          </>
        );
      case 'randomize':
        return (
          <>
            <Form.Field
              control={Checkbox}
              label='保持公私域划分'
              checked={operator.ip_random_preserve_scope !== false}
              onChange={(e, { checked }) => onChange({ ...operator, ip_random_preserve_scope: checked })}
            />
            <Form.Field
              control={Checkbox}
              label='允许私有地址跨类变换'
              checked={operator.ip_random_cross_class !== false}
              onChange={(e, { checked }) => onChange({ ...operator, ip_random_cross_class: checked })}
            />
            <Form.Field
              control={Input}
              label='公网地址保留前缀位数'
              type='number'
              min={0}
              max={24}
              value={operator.ip_random_preserve_bits || 0}
              onChange={(e) => onChange({ ...operator, ip_random_preserve_bits: parseInt(e.target.value) || 0 })}
              style={{ width: '120px' }}
            />
          </>
        );
      case 'tokenize':
        return (
          <>
            <Form.Field
              control={Input}
              label='Token 长度'
              type='number'
              min={4}
              max={64}
              value={operator.token_length || 16}
              onChange={(e) => onChange({ ...operator, token_length: parseInt(e.target.value) || 16 })}
              style={{ width: '120px' }}
            />
            <Form.Field
              control={Input}
              label='Token 字符集'
              value={operator.token_chars || 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'}
              onChange={(e) => onChange({ ...operator, token_chars: e.target.value })}
              style={{ minWidth: '300px' }}
            />
          </>
        );
      default:
        return null;
    }
  };

  if (loading) {
    return (
      <div className='dashboard-container'>
        <Segment loading>
          <p>加载中...</p>
        </Segment>
      </div>
    );
  }

  return (
    <div className='dashboard-container'>
      <Card fluid className='chart-card'>
        <Card.Content>
          <Card.Header className='header'>脱敏策略配置</Card.Header>

          <Message info>
            配置保存后立即生效。同一会话中的敏感词会保持一致的代号映射。
          </Message>

          {/* 基础设置 */}
          <Header as='h3'>基础设置</Header>
          <Form>
            <Form.Group>
              <Form.Field
                control={Checkbox}
                label='启用脱敏'
                checked={config.enabled}
                onChange={(e, { checked }) => updateConfig('enabled', checked)}
              />
              <Form.Field
                control={Checkbox}
                label='Fail-closed（脱敏异常时阻断请求）'
                checked={config.fail_closed}
                onChange={(e, { checked }) => updateConfig('fail_closed', checked)}
              />
              <Form.Field
                control={Checkbox}
                label='记录原始请求/响应（仅调试使用，会记录敏感信息）'
                checked={config.log_raw_requests}
                onChange={(e, { checked }) => updateConfig('log_raw_requests', checked)}
              />
            </Form.Group>
            <Form.Group>
              <Form.Field
                control={Input}
                label='最大文本长度（字节）'
                type='number'
                value={config.max_text_length}
                onChange={(e) => updateConfig('max_text_length', parseInt(e.target.value) || 0)}
              />
              <Form.Field
                control={Input}
                label='状态过期时间（小时）'
                type='number'
                value={config.cache_ttl_hours}
                onChange={(e) => updateConfig('cache_ttl_hours', parseInt(e.target.value) || 0)}
              />
            </Form.Group>
            <Form.Group>
              <Form.Field
                control={Dropdown}
                label='代号风格'
                selection
                options={codeStyleOptions}
                value={config.code_style}
                onChange={(e, { value }) => updateConfig('code_style', value)}
                style={{ minWidth: '220px' }}
              />
              {config.code_style === 'RAND' && (
                <>
                  <Form.Field
                    control={Input}
                    label='默认前缀'
                    value={config.code_prefix}
                    onChange={(e) => updateConfig('code_prefix', e.target.value)}
                  />
                  <Form.Field
                    control={Input}
                    label='随机长度'
                    type='number'
                    value={config.code_length}
                    onChange={(e) => updateConfig('code_length', parseInt(e.target.value) || 0)}
                  />
                </>
              )}
            </Form.Group>
          </Form>

          {/* 内置实体 */}
          <Header as='h3'>内置实体规则</Header>
          <Table celled>
            <Table.Header>
              <Table.Row>
                <Table.HeaderCell>启用</Table.HeaderCell>
                <Table.HeaderCell>实体类型</Table.HeaderCell>
                <Table.HeaderCell>名称</Table.HeaderCell>
                <Table.HeaderCell>操作符</Table.HeaderCell>
                <Table.HeaderCell>操作符配置</Table.HeaderCell>
                <Table.HeaderCell>操作</Table.HeaderCell>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {config.built_in_entities.map((entity, idx) => (
                <Table.Row key={entity.type || idx}>
                  <Table.Cell>
                    <Checkbox
                      checked={entity.enabled}
                      onChange={(e, { checked }) => updateBuiltInEntity(idx, 'enabled', checked)}
                    />
                  </Table.Cell>
                  <Table.Cell>{entity.type}</Table.Cell>
                  <Table.Cell>{entity.name}</Table.Cell>
                  <Table.Cell>
                    <Dropdown
                      selection
                      options={operatorOptions}
                      value={normalizeOperatorType(entity.operator?.type)}
                      onChange={(e, { value }) => updateBuiltInOperator(idx, value)}
                      style={{ minWidth: '180px' }}
                    />
                  </Table.Cell>
                  <Table.Cell>
                    {renderOperatorConfig(entity.operator || { type: 'symbolize' }, (updated) => updateBuiltInOperatorConfig(idx, updated))}
                  </Table.Cell>
                  <Table.Cell>
                    <Button
                      icon
                      basic
                      color='blue'
                      size='small'
                      title='复制为自定义正则规则'
                      onClick={() => copyBuiltinToDynamic(entity)}
                    >
                      <Icon name='copy' />
                    </Button>
                  </Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table>

          {/* 静态规则 */}
          <Header as='h3'>自定义关键词规则</Header>
          <Button icon labelPosition='left' onClick={() => addRule('static')} size='small'>
            <Icon name='plus' /> 添加关键词规则
          </Button>
          <Table celled>
            <Table.Header>
              <Table.Row>
                <Table.HeaderCell>规则ID</Table.HeaderCell>
                <Table.HeaderCell>名称</Table.HeaderCell>
                <Table.HeaderCell>关键词</Table.HeaderCell>
                <Table.HeaderCell>实体类型</Table.HeaderCell>
                <Table.HeaderCell>操作符</Table.HeaderCell>
                <Table.HeaderCell>操作</Table.HeaderCell>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {config.static_rules.map((rule, idx) => (
                <Table.Row key={idx}>
                  <Table.Cell>
                    <Input
                      value={rule.id}
                      onChange={(e) => updateRule('static', idx, 'id', e.target.value)}
                      size='small'
                    />
                  </Table.Cell>
                  <Table.Cell>
                    <Input
                      value={rule.name}
                      onChange={(e) => updateRule('static', idx, 'name', e.target.value)}
                      size='small'
                    />
                  </Table.Cell>
                  <Table.Cell>
                    <Input
                      value={rule.keyword || ''}
                      onChange={(e) => updateRule('static', idx, 'keyword', e.target.value)}
                      size='small'
                    />
                  </Table.Cell>
                  <Table.Cell>
                    <Input
                      value={rule.entity_type}
                      onChange={(e) => updateRule('static', idx, 'entity_type', e.target.value)}
                      size='small'
                    />
                  </Table.Cell>
                  <Table.Cell>
                    <Dropdown
                      selection
                      options={operatorOptions}
                      value={normalizeOperatorType(rule.operator?.type)}
                      onChange={(e, { value }) => updateRuleOperator('static', idx, value)}
                      style={{ minWidth: '180px' }}
                    />
                  </Table.Cell>
                  <Table.Cell>
                    <Button icon color='red' size='small' onClick={() => removeRule('static', idx)}>
                      <Icon name='trash' />
                    </Button>
                  </Table.Cell>
                </Table.Row>
              ))}
              {config.static_rules.length === 0 && (
                <Table.Row>
                  <Table.Cell colSpan='6' textAlign='center'>
                    暂无自定义关键词规则
                  </Table.Cell>
                </Table.Row>
              )}
            </Table.Body>
          </Table>

          {/* 动态规则 */}
          <Header as='h3'>自定义正则规则</Header>
          <Button icon labelPosition='left' onClick={() => addRule('dynamic')} size='small'>
            <Icon name='plus' /> 添加正则规则
          </Button>
          <Table celled>
            <Table.Header>
              <Table.Row>
                <Table.HeaderCell>规则ID</Table.HeaderCell>
                <Table.HeaderCell>名称</Table.HeaderCell>
                <Table.HeaderCell>正则表达式</Table.HeaderCell>
                <Table.HeaderCell>实体类型</Table.HeaderCell>
                <Table.HeaderCell>操作符</Table.HeaderCell>
                <Table.HeaderCell>操作</Table.HeaderCell>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {config.dynamic_rules.map((rule, idx) => (
                <Table.Row key={idx}>
                  <Table.Cell>
                    <Input
                      value={rule.id}
                      onChange={(e) => updateRule('dynamic', idx, 'id', e.target.value)}
                      size='small'
                    />
                  </Table.Cell>
                  <Table.Cell>
                    <Input
                      value={rule.name}
                      onChange={(e) => updateRule('dynamic', idx, 'name', e.target.value)}
                      size='small'
                    />
                  </Table.Cell>
                  <Table.Cell>
                    <Input
                      value={rule.pattern || ''}
                      onChange={(e) => updateRule('dynamic', idx, 'pattern', e.target.value)}
                      size='small'
                      placeholder='正则表达式'
                    />
                  </Table.Cell>
                  <Table.Cell>
                    <Input
                      value={rule.entity_type}
                      onChange={(e) => updateRule('dynamic', idx, 'entity_type', e.target.value)}
                      size='small'
                    />
                  </Table.Cell>
                  <Table.Cell>
                    <Dropdown
                      selection
                      options={operatorOptions}
                      value={normalizeOperatorType(rule.operator?.type)}
                      onChange={(e, { value }) => updateRuleOperator('dynamic', idx, value)}
                      style={{ minWidth: '180px' }}
                    />
                  </Table.Cell>
                  <Table.Cell>
                    <Button icon color='red' size='small' onClick={() => removeRule('dynamic', idx)}>
                      <Icon name='trash' />
                    </Button>
                  </Table.Cell>
                </Table.Row>
              ))}
              {config.dynamic_rules.length === 0 && (
                <Table.Row>
                  <Table.Cell colSpan='6' textAlign='center'>
                    暂无自定义正则规则
                  </Table.Cell>
                </Table.Row>
              )}
            </Table.Body>
          </Table>

          <Button primary loading={saving} onClick={saveConfig}>
            保存配置
          </Button>

          {/* 预览区域 */}
          <Header as='h3'>效果预览</Header>
          <Segment>
            <Form>
              <Form.Field
                control={TextArea}
                label='原始文本'
                placeholder='输入要测试的文本...'
                value={previewText}
                onChange={(e) => setPreviewText(e.target.value)}
                rows={3}
              />
              <Form.Group>
                <Form.Field
                  control={Input}
                  label='会话ID（用于保持同一会话映射一致）'
                  value={previewSession}
                  onChange={(e) => setPreviewSession(e.target.value)}
                  style={{ minWidth: '300px' }}
                />
                <Form.Field>
                  <label>&nbsp;</label>
                  <Button primary loading={previewLoading} onClick={runPreview}>
                    测试脱敏
                  </Button>
                </Form.Field>
              </Form.Group>
            </Form>

            {previewResult && (
              <>
                <Header as='h4'>脱敏结果</Header>
                <Segment>
                  <p>{previewResult.masked || '（无变化）'}</p>
                </Segment>

                <Header as='h4'>恢复结果</Header>
                <Segment>
                  <p>{previewResult.restored || '（无变化）'}</p>
                </Segment>

                {previewResult.mappings && previewResult.mappings.length > 0 && (
                  <>
                    <Header as='h4'>映射表</Header>
                    <Table celled compact>
                      <Table.Header>
                        <Table.Row>
                          <Table.HeaderCell>代号</Table.HeaderCell>
                          <Table.HeaderCell>原始值</Table.HeaderCell>
                          <Table.HeaderCell>类型</Table.HeaderCell>
                        </Table.Row>
                      </Table.Header>
                      <Table.Body>
                        {previewResult.mappings.map((m, idx) => (
                          <Table.Row key={idx}>
                            <Table.Cell><code>{m.code}</code></Table.Cell>
                            <Table.Cell>{m.original}</Table.Cell>
                            <Table.Cell>{m.type}</Table.Cell>
                          </Table.Row>
                        ))}
                      </Table.Body>
                    </Table>
                  </>
                )}
              </>
            )}
          </Segment>
        </Card.Content>
      </Card>
    </div>
  );
};

export default MaskingSetting;
