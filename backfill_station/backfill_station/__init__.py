"""采集回补台（offline-replayable collection backfill station）。

核心不变量：
  已确认实付 + 所有未终止许可的封顶保留 <= 批次网闸字节额度
"""

__version__ = "1.0.0"
